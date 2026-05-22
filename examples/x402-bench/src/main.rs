//! AgentDebitNote x402 benchmark harness.
//!
//! Measures end-to-end latency for the ADN payment flow:
//! Agent signs debit → merchant relays to facilitator → resource delivered.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::Engine;
use clap::Parser;
use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::utils::serde::Deserializable;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(about = "AgentDebitNote x402 benchmark")]
struct Args {
    #[arg(long, default_value = "bench.toml")]
    config: PathBuf,
    #[arg(long)]
    payments: Option<usize>,
    #[arg(long)]
    merchant_url: Option<String>,
    #[arg(long)]
    out_dir: Option<PathBuf>,
    #[arg(long)]
    setup_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct SetupReport {
    merchant_id_hex: String,
    agents: Vec<SetupAgentRecord>,
    #[serde(default)]
    adn_note_id: Option<String>,
    #[serde(default)]
    adn_serial_num_hex: Option<[String; 4]>,
    #[serde(default)]
    adn_balance: Option<u64>,
    #[serde(default)]
    adn_expiry_block: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct SetupAgentRecord {
    hot_key_path: String,
}

struct PaymentRow {
    seq: u64,
    t_get1: u64,
    t_402: u64,
    t_sign_start: u64,
    t_sign_end: u64,
    t_send: u64,
    t_delivered: u64,
    ok: bool,
    error: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let payments = args.payments.unwrap_or(5);
    let merchant_url = args.merchant_url.unwrap_or_else(|| "http://localhost:7001".into());
    let out_base = args.out_dir.unwrap_or_else(|| PathBuf::from("./bench-out"));

    let report: SetupReport = toml::from_str(
        &std::fs::read_to_string(args.setup_dir.join("setup.toml"))?
    )?;

    let note_id = report.adn_note_id.as_ref().context("missing adn_note_id")?;
    let serial_hex = report.adn_serial_num_hex.as_ref().context("missing adn_serial_num_hex")?;
    let balance = report.adn_balance.context("missing adn_balance")?;
    let expiry = report.adn_expiry_block.context("missing adn_expiry_block")?;

    let serial: miden_protocol::Word = [
        Felt::new(u64::from_str_radix(serial_hex[0].trim_start_matches("0x"), 16)?),
        Felt::new(u64::from_str_radix(serial_hex[1].trim_start_matches("0x"), 16)?),
        Felt::new(u64::from_str_radix(serial_hex[2].trim_start_matches("0x"), 16)?),
        Felt::new(u64::from_str_radix(serial_hex[3].trim_start_matches("0x"), 16)?),
    ].into();

    let sk_bytes = std::fs::read(args.setup_dir.join(&report.agents[0].hot_key_path))?;
    let sk = SecretKey::read_from_bytes(&sk_bytes).map_err(|e| anyhow::anyhow!("key: {e}"))?;
    let agent_sk = miden_protocol::account::auth::AuthSecretKey::Falcon512Poseidon2(sk);
    let merchant_id = AccountId::from_hex(&report.merchant_id_hex)?;

    let client = adn_client::client::AdnClient::new(
        agent_sk, note_id.clone(), serial, balance, expiry,
    );

    let http = reqwest::Client::builder().user_agent("x402-bench/0.1").build()?;
    let resource_url = format!("{}/resource", merchant_url.trim_end_matches('/'));
    let run_id = format!("run-{}", now_secs());
    let out_dir = out_base.join(&run_id);
    std::fs::create_dir_all(&out_dir)?;

    let mut rows = Vec::new();
    for i in 0..payments {
        let t_get1 = now_micros();
        let res = http.get(&resource_url).send().await?;
        let t_402 = now_micros();
        if res.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            anyhow::bail!("expected 402, got {}", res.status());
        }
        drop(res);

        let (debit, timings) = client.sign_debit(merchant_id, 100)
            .map_err(|e| anyhow::anyhow!("sign: {e}"))?;
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&debit)?);

        let t_send = now_micros();
        let res2 = http.get(&resource_url)
            .header("payment-signature", b64).send().await?;
        let t_delivered = now_micros();
        let ok = res2.status().is_success();
        let error = if !ok { res2.text().await.unwrap_or_default() } else { String::new() };

        rows.push(PaymentRow {
            seq: i as u64, t_get1, t_402,
            t_sign_start: timings.t_sign_start, t_sign_end: timings.t_sign_end,
            t_send, t_delivered, ok, error,
        });
    }

    write_csv(&out_dir.join("payments.csv"), &rows)?;
    write_summary(&out_dir.join("summary.csv"), &rows)?;
    tracing::info!(out_dir = %out_dir.display(), payments = rows.len(), "bench complete");
    Ok(())
}

fn write_csv(path: &std::path::Path, rows: &[PaymentRow]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    writeln!(f, "seq,t_get1,t_402,t_sign_start,t_sign_end,t_send,t_delivered,d_402_us,d_sign_us,d_hot_path_us,d_total_us,ok,error")?;
    for r in rows {
        writeln!(f, "{},{},{},{},{},{},{},{},{},{},{},{},{}", r.seq, r.t_get1, r.t_402,
            r.t_sign_start, r.t_sign_end, r.t_send, r.t_delivered,
            r.t_402.saturating_sub(r.t_get1), r.t_sign_end.saturating_sub(r.t_sign_start),
            r.t_delivered.saturating_sub(r.t_send), r.t_delivered.saturating_sub(r.t_get1),
            r.ok, r.error)?;
    }
    Ok(())
}

fn write_summary(path: &std::path::Path, rows: &[PaymentRow]) -> anyhow::Result<()> {
    use std::io::Write;
    let ok: Vec<_> = rows.iter().filter(|r| r.ok).collect();
    let total: Vec<u64> = ok.iter().map(|r| r.t_delivered.saturating_sub(r.t_get1)).collect();
    let hot: Vec<u64> = ok.iter().map(|r| r.t_delivered.saturating_sub(r.t_send)).collect();
    let sign: Vec<u64> = ok.iter().map(|r| r.t_sign_end.saturating_sub(r.t_sign_start)).collect();
    let mut f = std::fs::File::create(path)?;
    writeln!(f, "metric,count,p50_us,p95_us,p99_us,mean_us,min_us,max_us")?;
    pctl(&mut f, "total_us", &total)?;
    pctl(&mut f, "hot_path_us", &hot)?;
    pctl(&mut f, "sign_us", &sign)?;
    writeln!(f, "ok_count,{},,,,,,", ok.len())?;
    writeln!(f, "error_count,{},,,,,,", rows.len() - ok.len())?;
    Ok(())
}

fn pctl<W: std::io::Write>(w: &mut W, name: &str, vals: &[u64]) -> anyhow::Result<()> {
    if vals.is_empty() { writeln!(w, "{name},0,,,,,,")?; return Ok(()); }
    let mut s = vals.to_vec(); s.sort_unstable();
    let n = s.len();
    let p = |q: f64| s[((n as f64 - 1.0) * q).round() as usize];
    let mean = s.iter().sum::<u64>() / n as u64;
    writeln!(w, "{name},{},{},{},{},{},{},{}", n, p(0.50), p(0.95), p(0.99), mean, s[0], s[n-1])?;
    Ok(())
}

fn now_micros() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0) }
fn now_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
