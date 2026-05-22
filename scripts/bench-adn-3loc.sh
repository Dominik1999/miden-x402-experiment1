#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# bench-adn-3loc.sh
#
# 3-location ADN benchmark:
#   - Facilitator: eu-west-1
#   - Merchant: us-east-1 (relays to facilitator)
#   - Agent/bench: local Mac
#
# Usage: bash scripts/bench-adn-3loc.sh
###############################################################################

REGION_FAC="eu-west-1"
REGION_MERCH="us-east-1"
INSTANCE_TYPE="c6i.xlarge"
SSH_USER="ubuntu"
REPO_URL="https://github.com/Dominik1999/miden-x402-experiment1.git"
BRANCH="main"
RUN_ID="adn-bench-$(date +%Y%m%d-%H%M%S)"
KEY_NAME="adn-bench-${RUN_ID}"
KEY_FILE="/tmp/${KEY_NAME}.pem"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"

INSTANCE_ID_FAC=""
INSTANCE_ID_MERCH=""
SG_ID_FAC=""
SG_ID_MERCH=""

log() { echo "[$(date '+%H:%M:%S')] $*"; }

ssh_cmd() { local ip="$1"; shift; ssh -i "$KEY_FILE" $SSH_OPTS "${SSH_USER}@${ip}" "$@"; }
scp_cmd() { scp -i "$KEY_FILE" $SSH_OPTS "$@"; }

find_ubuntu_ami() {
  aws ec2 describe-images --region "$1" --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
              "Name=state,Values=available" "Name=architecture,Values=x86_64" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text
}

cleanup() {
  echo ""
  log "=== Cleanup ==="
  [[ -n "$INSTANCE_ID_FAC" ]] && { log "Terminating facilitator..."; aws ec2 terminate-instances --region "$REGION_FAC" --instance-ids "$INSTANCE_ID_FAC" &>/dev/null || true; }
  [[ -n "$INSTANCE_ID_MERCH" ]] && { log "Terminating merchant..."; aws ec2 terminate-instances --region "$REGION_MERCH" --instance-ids "$INSTANCE_ID_MERCH" &>/dev/null || true; }
  [[ -n "$INSTANCE_ID_FAC" ]] && { aws ec2 wait instance-terminated --region "$REGION_FAC" --instance-ids "$INSTANCE_ID_FAC" &>/dev/null || true; }
  [[ -n "$INSTANCE_ID_MERCH" ]] && { aws ec2 wait instance-terminated --region "$REGION_MERCH" --instance-ids "$INSTANCE_ID_MERCH" &>/dev/null || true; }
  [[ -n "$SG_ID_FAC" ]] && { aws ec2 delete-security-group --region "$REGION_FAC" --group-id "$SG_ID_FAC" &>/dev/null || true; }
  [[ -n "$SG_ID_MERCH" ]] && { aws ec2 delete-security-group --region "$REGION_MERCH" --group-id "$SG_ID_MERCH" &>/dev/null || true; }
  aws ec2 delete-key-pair --region "$REGION_FAC" --key-name "$KEY_NAME" &>/dev/null || true
  aws ec2 delete-key-pair --region "$REGION_MERCH" --key-name "$KEY_NAME" &>/dev/null || true
  rm -f "$KEY_FILE"
  log "Cleanup complete"
}
trap cleanup EXIT

###############################################################################
log "============================================"
log "  ADN 3-Location Benchmark"
log "  Facilitator: ${REGION_FAC}"
log "  Merchant:    ${REGION_MERCH}"
log "  Agent:       local"
log "  Run ID:      ${RUN_ID}"
log "============================================"
echo ""

# ── Phase 1: Provision ──
log "Phase 1: Provisioning..."

aws ec2 create-key-pair --region "$REGION_FAC" --key-name "$KEY_NAME" --key-type ed25519 \
  --query 'KeyMaterial' --output text > "$KEY_FILE"
chmod 600 "$KEY_FILE"
aws ec2 import-key-pair --region "$REGION_MERCH" --key-name "$KEY_NAME" \
  --public-key-material fileb://<(ssh-keygen -y -f "$KEY_FILE") >/dev/null

for REGION in "$REGION_FAC" "$REGION_MERCH"; do
  SG_NAME="adn-bench-sg-${RUN_ID}-${REGION}"
  SG_ID=$(aws ec2 create-security-group --region "$REGION" --group-name "$SG_NAME" \
    --description "ADN bench ${RUN_ID}" --query 'GroupId' --output text)
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --ip-permissions \
      "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]" \
      "IpProtocol=tcp,FromPort=7001,ToPort=7002,IpRanges=[{CidrIp=0.0.0.0/0}]" \
      "IpProtocol=icmp,FromPort=-1,ToPort=-1,IpRanges=[{CidrIp=0.0.0.0/0}]" >/dev/null
  if [[ "$REGION" == "$REGION_FAC" ]]; then SG_ID_FAC="$SG_ID"; else SG_ID_MERCH="$SG_ID"; fi
done

AMI_FAC=$(find_ubuntu_ami "$REGION_FAC")
AMI_MERCH=$(find_ubuntu_ami "$REGION_MERCH")

INSTANCE_ID_FAC=$(aws ec2 run-instances --region "$REGION_FAC" --image-id "$AMI_FAC" \
  --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" --security-group-ids "$SG_ID_FAC" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3}" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=adn-facilitator-${RUN_ID}}]" \
  --query 'Instances[0].InstanceId' --output text)

INSTANCE_ID_MERCH=$(aws ec2 run-instances --region "$REGION_MERCH" --image-id "$AMI_MERCH" \
  --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" --security-group-ids "$SG_ID_MERCH" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3}" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=adn-merchant-${RUN_ID}}]" \
  --query 'Instances[0].InstanceId' --output text)

log "Waiting for instances..."
aws ec2 wait instance-running --region "$REGION_FAC" --instance-ids "$INSTANCE_ID_FAC" &
aws ec2 wait instance-running --region "$REGION_MERCH" --instance-ids "$INSTANCE_ID_MERCH" &
wait

FAC_IP=$(aws ec2 describe-instances --region "$REGION_FAC" --instance-ids "$INSTANCE_ID_FAC" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
MERCH_IP=$(aws ec2 describe-instances --region "$REGION_MERCH" --instance-ids "$INSTANCE_ID_MERCH" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

log "Facilitator: ${FAC_IP} (${REGION_FAC})"
log "Merchant:    ${MERCH_IP} (${REGION_MERCH})"

# Wait for SSH
for IP in "$FAC_IP" "$MERCH_IP"; do
  for i in $(seq 1 60); do
    ssh_cmd "$IP" "echo ok" &>/dev/null && break
    sleep 5
  done
done
log "SSH ready on both."
echo ""

# ── Phase 2: Build on both (parallel) ──
log "Phase 2: Building on both instances (10-15 min)..."

SETUP_SCRIPT='#!/bin/bash
set -euo pipefail
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential pkg-config libssl-dev cmake git libpq-dev protobuf-compiler curl
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.93.0
. "$HOME/.cargo/env"
git clone --depth 1 --branch '"$BRANCH"' '"$REPO_URL"' ~/miden-x402
cd ~/miden-x402
cargo build --release -p x402-facilitator-server -p reference-merchant -p setup-testnet 2>&1 | tail -3
echo "=== Build done ==="'

ssh_cmd "$FAC_IP" "$SETUP_SCRIPT" 2>&1 | sed 's/^/  [fac]  /' &
PID_FAC=$!
ssh_cmd "$MERCH_IP" "$SETUP_SCRIPT" 2>&1 | sed 's/^/  [merch] /' &
PID_MERCH=$!
wait $PID_FAC; log "Facilitator build done."
wait $PID_MERCH; log "Merchant build done."
echo ""

# ── Phase 3: Start facilitator FIRST (needed for setup-testnet to fetch pubkey) ──
log "Phase 3: Starting facilitator on ${FAC_IP}:7002..."
ssh_cmd "$FAC_IP" "bash -lc '
  cd ~/miden-x402
  mkdir -p fac-data
  nohup env FACILITATOR_DATA_DIR=./fac-data FACILITATOR_HTTP_PORT=7002 \
    MIDEN_RPC_ENDPOINT=https://rpc.testnet.miden.io RUST_LOG=info \
    ./target/release/x402-facilitator-server > facilitator.log 2>&1 &
'"

for i in $(seq 1 60); do
  ssh_cmd "$FAC_IP" "grep -q 'listening' ~/miden-x402/facilitator.log 2>/dev/null" 2>/dev/null && break
  sleep 5
done
log "Facilitator listening."

# ── Phase 4: Setup testnet accounts + AgentDebitNote ──
log "Phase 4: Setting up testnet accounts + AgentDebitNote..."

ssh_cmd "$FAC_IP" "bash -lc '
  cd ~/miden-x402
  ./target/release/setup-testnet --agents 1 --mint-amount 1000000 \
    --adn --adn-amount 100000 \
    --out-dir ./testnet-state 2>&1
'"  2>&1 | sed 's/^/  [setup] /'

# Read setup.toml
SETUP_TOML=$(ssh_cmd "$FAC_IP" 'cat ~/miden-x402/testnet-state/setup.toml')
echo "$SETUP_TOML" | sed 's/^/    /'

MERCHANT_ID=$(echo "$SETUP_TOML" | sed -n 's/^merchant_id_hex *= *"\([^"]*\)".*/\1/p' | head -1)
FAUCET_ID=$(echo "$SETUP_TOML" | sed -n 's/^faucet_id_hex *= *"\([^"]*\)".*/\1/p' | head -1)
log "Merchant ID: ${MERCHANT_ID}"
log "Faucet ID:   ${FAUCET_ID}"

# ── Phase 5: Start merchant (points to facilitator) ──
log "Phase 5: Starting merchant on ${MERCH_IP}:7001 → facilitator at ${FAC_IP}:7002..."
ssh_cmd "$MERCH_IP" "bash -lc '
  cd ~/miden-x402
  nohup env MERCHANT_ACCOUNT_ID=${MERCHANT_ID} MERCHANT_ASSET_FAUCET_ID=${FAUCET_ID} \
    MERCHANT_PRICE_AMOUNT=100 MERCHANT_HTTP_PORT=7001 \
    FACILITATOR_URL=http://${FAC_IP}:7002 RUST_LOG=info \
    ./target/release/reference-merchant > merchant.log 2>&1 &
'"

for i in $(seq 1 60); do
  ssh_cmd "$MERCH_IP" "grep -q 'listening' ~/miden-x402/merchant.log 2>/dev/null" 2>/dev/null && break
  sleep 5
done
log "Merchant listening."
echo ""

# ── Phase 6: Download testnet-state for local agent ──
log "Phase 6: Downloading testnet-state for local agent..."
LOCAL_STATE="/tmp/adn-testnet-state-${RUN_ID}"
mkdir -p "$LOCAL_STATE"
scp_cmd -r "${SSH_USER}@${FAC_IP}:~/miden-x402/testnet-state/*" "${LOCAL_STATE}/"
log "Saved to ${LOCAL_STATE}"
echo ""

# ── Phase 7: Measure RTTs ──
log "Phase 7: Measuring network RTTs..."
echo ""
log "Local → Merchant (${MERCH_IP}):"
ping -c 5 "$MERCH_IP" 2>&1 | tail -2 | sed 's/^/  /'
echo ""
log "Local → Facilitator (${FAC_IP}):"
ping -c 5 "$FAC_IP" 2>&1 | tail -2 | sed 's/^/  /'
echo ""
log "Merchant → Facilitator:"
ssh_cmd "$MERCH_IP" "ping -c 5 ${FAC_IP}" 2>&1 | tail -2 | sed 's/^/  /'
echo ""

# ── Phase 8: Build bench locally + run ──
log "Phase 8: Building bench locally..."
cd /Users/domi2000/Repos/miden-x402-experiment1
RUSTFLAGS="-L /opt/homebrew/opt/libpq/lib" cargo build --release -p x402-bench 2>&1 | tail -3

log "Running ADN benchmark (50 payments)..."
./target/release/x402-bench \
  --setup-dir "$LOCAL_STATE" \
  --merchant-url "http://${MERCH_IP}:7001" \
  --payments 50 \
  --out-dir "./bench-results-${RUN_ID}" 2>&1 | sed 's/^/  /'

echo ""
log "=== Results ==="

# Find and print summary
SUMMARY=$(find "./bench-results-${RUN_ID}" -name "summary.csv" | sort | tail -1)
if [[ -n "$SUMMARY" ]]; then
  log "summary.csv:"
  cat "$SUMMARY"
  echo ""
  log "payments.csv:"
  cat "$(dirname "$SUMMARY")/payments.csv"
fi

echo ""
echo "============================================"
echo "  ADN Benchmark Complete"
echo "  Facilitator: ${INSTANCE_ID_FAC} (${FAC_IP}) in ${REGION_FAC}"
echo "  Merchant:    ${INSTANCE_ID_MERCH} (${MERCH_IP}) in ${REGION_MERCH}"
echo "  Results:     ./bench-results-${RUN_ID}/"
echo "============================================"
echo ""
echo "Terminate instances and clean up? [y/N]"
read -r CONFIRM
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
  exit 0
else
  log "Keeping instances running. Manual cleanup:"
  echo "  aws ec2 terminate-instances --region ${REGION_FAC} --instance-ids ${INSTANCE_ID_FAC}"
  echo "  aws ec2 terminate-instances --region ${REGION_MERCH} --instance-ids ${INSTANCE_ID_MERCH}"
  INSTANCE_ID_FAC="" INSTANCE_ID_MERCH="" SG_ID_FAC="" SG_ID_MERCH=""
  exit 0
fi
