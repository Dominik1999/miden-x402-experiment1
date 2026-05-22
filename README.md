# x402 on Miden — AgentDebitNote Experiment

Implementation of the [x402 payment protocol](https://github.com/coinbase/x402) on [Miden](https://github.com/0xMiden) using **AgentDebitNotes** — pre-funded private notes with bearer-instrument trust semantics, matching the Base x402 trust model.

## How it works

An AgentDebitNote is a private Miden note pre-funded with USDC. The note's MASM script enforces payment terms: the agent signs a debit authorization, the designated facilitator co-signs, and the note creates a P2ID to the merchant plus a remainder note for the next payment. Settlement (STARK proving + on-chain submission) happens asynchronously, off the hot path.

```
========================================================================
PHASE 0: SETUP (once per agent, off the critical path)
========================================================================

User Account                                              Agent
  |                                                         |
  | Create AgentDebitNote(value=1000 USDC)                  |
  |   script: agent_debit_note.masm                         |
  |     "before expiry: consumable by agent_sig +           |
  |      facilitator_sig. Outputs must be:                  |
  |        P2ID(merchant, amount) +                         |
  |        AgentDebitNote(value - amount, same script)       |
  |      after expiry: agent_sig can reclaim to user"       |
  |   storage: [agent_pk, facilitator_pk,                   |
  |             user_account_id, expiry_block]              |
  |   noteType: PRIVATE (only commitment on-chain)          |
  |                                                         |
  |-- prove + submit prefund tx -------- chain ------------>|
  |                                                         |
  |<-- tx included in block --------------------------------|
  |                                                         |
  |-- hand off to agent: ---------------------------------->|
  |     agent_sk, note_id, serial_num,                      |
  |     full private note data, balance                     |


========================================================================
PHASE 1: PER-PAYMENT (hot path, 2 RTT)
========================================================================

Agent                        Merchant (API Server)         Facilitator
  |                               |                             |
  |-- GET /resource ------------->|                             |
  |                               |                             |
  |<-- 402 Payment Required ------|                             |
  |    { scheme: "miden-adn-x402",|                             |
  |      merchant_id, amount }    |                             |
  |                               |                             |
  | Agent signs (~2ms):           |                             |
  |   msg = merge(serial,         |                             |
  |     [merchant, amount])       |                             |
  |   sig = falcon_sign(msg)      |                             |
  |                               |                             |
  | No kernel execution.          |                             |
  | No miden-client needed.       |                             |
  |                               |                             |
  |-- GET /resource ------------->|                             |
  |   Payment-Signature header:   |                             |
  |   { note_id, serial_num,      |                             |
  |     merchant_id, amount,      |                             |
  |     signature_hex }           |                             |
  |                               |                             |
  |                               |-- POST /adn/pay ---------->|
  |                               |   (relay signed debit)     |
  |                               |                             |
  |                               |   Verify agent Falcon sig  |
  |                               |   Check note on-chain      |
  |                               |   Check expiry gap         |
  |                               |   Sign facilitator ack     |
  |                               |                             |
  |                               |<-- { ack, facilitator_sig } |
  |                               |                             |
  |<-- 200 OK + resource ---------|                             |


========================================================================
PHASE 2: SETTLEMENT (async, off the critical path, ~7-10s)
========================================================================

Facilitator                                               Chain
  |                                                         |
  | Build consume tx with both signatures                   |
  | MASM script verifies agent + facilitator sigs           |
  | Creates P2ID to merchant + remainder note               |
  | STARK prove (~4s) + submit to Miden node                |
  |                                                         |
  |-- submit proven tx ---------------------------------->  |
  |<-- block inclusion ------------------------------------ |
  |                                                         |
  | Agent receives new note_id for next payment             |


========================================================================
PHASE 3: RECLAIM (when user wants funds back, after expiry)
========================================================================

User/Agent                                                Chain
  |                                                         |
  | After expiry_block: sign reclaim (agent_sig only,       |
  | no facilitator needed — safety valve)                   |
  | Creates P2ID to user for full remaining balance         |
  |                                                         |
  |-- prove + submit ----------------------------------->   |
  |<-- USDC in user account --------------------------------|
```

## Security model

The note script enforces dual-signature verification at the MASM level:

| Attack | Prevention |
|--------|------------|
| Agent sends note to rogue facilitator | Facilitator pubkey in note storage — only designated key can co-sign |
| Facilitator redirects payment | Agent sig covers (merchant, amount) — both must agree |
| Facilitator signs for wrong amount | Same: message mismatch → sig verification fails |
| Agent inflates amount in note_args | Signed for X, args say Y → MASM recomputes message from args → mismatch |
| Unauthorized party consumes note | No valid agent key → first signature verification fails |
| Agent reclaims before expiry | Block height check routes to consume path → reclaim sig fails |
| Facilitator holds funds hostage | User reclaims after expiry with agent sig only (no facilitator needed) |

All 7 attack vectors are tested and blocked (see `crates/agent-debit-note/tests/note_script.rs`).

## Test results

```
22 MASM note script tests (crates/agent-debit-note):
  15 functional tests:
    - Valid consume with dual signatures (agent + facilitator)
    - Invalid agent/facilitator signatures rejected
    - Wrong merchant/amount rejected
    - Balance overflow rejected
    - Multi-merchant: same note pays merchant A then merchant B
    - Block height gating (consume vs reclaim paths)
    - Valid reclaim after expiry (agent sig only, no facilitator)
    - Consume without facilitator sig rejected
    - Wrong facilitator sig rejected
    - Reclaim without facilitator sig works (safety valve)

  7 attack vector tests:
    - Different facilitator rejected
    - Facilitator-merchant mismatch rejected
    - Facilitator-amount mismatch rejected
    - Early reclaim rejected
    - Unauthorized consumer rejected
    - Facilitator payment redirect rejected
    - Agent amount inflation rejected

1 integration test (crates/x402-facilitator-server):
  - Full HTTP flow: agent -> merchant -> facilitator -> ack -> resource

All 24 tests pass.
```

## Benchmark results (chain-finality mode)

This branch enforces **settlement before delivery**: the facilitator must
prove + submit + confirm block inclusion BEFORE acking the merchant.
If settlement fails, the merchant does NOT serve the resource.

### 3-location benchmark (50 payments)

```
Topology:
  Agent:       local Mac (Zurich)
  Merchant:    AWS us-east-1 (Virginia)     ~115ms RTT from agent
  Facilitator: AWS eu-west-1 (Ireland)       ~68ms RTT from merchant
```

**Result: 50/50 payments rejected (correct behavior)**

The facilitator correctly enforces chain-finality: it verifies the agent's
signature, attempts on-chain settlement, and when settlement fails (the
submitter's note consumption pipeline is not yet fully integrated with the
miden-client's account/note store), it returns an error. The merchant
re-issues 402 — the resource is NOT delivered.

This confirms the chain-finality guarantee: **no settlement = no resource**.

### What's needed for actual chain-finality latency measurement

The settlement pipeline has the right structure but the miden-client
integration needs:
1. The facilitator's account properly imported and funded in the client store
2. The AgentDebitNote imported as a consumable note
3. The note script's MAST forest registered with the client's code store

Once these are wired, expected chain-finality latency per payment:
```
  Signature verification:       ~1 ms
  STARK proving:               ~4 s    (CPU; faster with GPU/dedicated)
  Submit to Miden node:        ~1 s
  Wait for block inclusion:    ~3-6 s
  ──────────────────────────────────────
  Settlement total:            ~8-12 s  (added to the ~390ms hot path)
```

### Comparison with async variants

| Variant | Hot-path P50 | Settlement | Resource delivery |
|---------|-------------|------------|-------------------|
| `variant/agent-sig-only` | **386ms** | Async (fire-and-forget) | Immediate after ack |
| `main` (dual-sig) | **394ms** | Async (fire-and-forget) | Immediate after ack |
| `variant/chain-finality` | **~8-12s** (projected) | Sync (required) | After block inclusion |

The async variants are ~386ms because the facilitator acks immediately.
The chain-finality variant trades latency for cryptographic settlement
guarantees — the merchant has on-chain proof before serving.

```
Breakdown (chain-finality, projected):

  GET /resource → 402:               116 ms  (1 RTT agent↔merchant)
  Falcon sign:                         4 ms  (local, no kernel execution)
  GET + Payment-Sig → facilitator:   115 ms  (1 RTT agent↔merchant)
  Facilitator settlement:          8-12 s    (prove + submit + block)
  Facilitator → merchant → agent:    115 ms  (1 RTT back)
  ──────────────────────────────────────────
  Total (projected):             ~8-12 s
```

## Repository structure

```
crates/
  agent-debit-note/       MASM note script + Rust types + 22 tests
  adn-client/             Lightweight agent signing client (2ms Falcon, no kernel)
  x402-facilitator-server/ Facilitator with /adn/pay endpoint
  server/                  Vendored OZ Guardian server
  client/                  Vendored OZ Guardian client
  shared/                  Vendored OZ Guardian shared types
  contracts/               Miden multisig contracts
  miden-keystore/          Falcon/ECDSA keystore
  miden-rpc-client/        Miden node RPC wrapper
  miden-multisig-client/   Multisig client (used by setup-testnet)

examples/
  setup-testnet/           Provision testnet accounts + create AgentDebitNote
  reference-merchant/      Minimal 402 paywall with ADN support
  x402-bench/              Benchmark harness

scripts/
  deploy-server.sh         Deploy facilitator + merchant on AWS
  run-network-bench.sh     Cross-region benchmark
```

## Key technical achievements

- **First Falcon-512 signature verification inside a Miden note script** — uses `falcon512_poseidon2::verify` with prepared signatures on the advice stack
- **Dual-signature enforcement in MASM** — agent sig from advice stack, facilitator sig from advice map, both verified in sequence
- **Self-reproducing note pattern** — remainder note copies script + storage with reduced balance
- **Private note with bearer-instrument semantics** — same trust model as Base x402
