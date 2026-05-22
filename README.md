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

## Measured latency

Measured on a real 3-location deployment (50 payments, 0 errors):

```
Topology:
  Agent:       local Mac (Zurich)
  Merchant:    AWS us-east-1 (Virginia)     114ms RTT from agent
  Facilitator: AWS eu-west-1 (Ireland)       68ms RTT from merchant
```

| Metric | P50 | P95 | P99 | Min | Max |
|--------|-----|-----|-----|-----|-----|
| **Total (402 → resource)** | **386ms** | 420ms | 812ms | 379ms | 812ms |
| **Hot path (send → resource)** | **265ms** | 302ms | 578ms | 263ms | 578ms |
| **Falcon signing** | **3.6ms** | 4.7ms | 5.1ms | 0.9ms | 5.1ms |

```
Breakdown (P50):

  GET /resource → 402:               114 ms  (1 RTT agent↔merchant)
  Falcon sign:                       3.6 ms  (local, no kernel execution)
  GET + Payment-Sig → 200:           265 ms  (1 RTT agent↔merchant 114ms
                                              + merchant↔facilitator relay 68ms
                                              + facilitator verify ~1ms
                                              + HTTP overhead)
  ──────────────────────────────────────────
  Total P50:                          386 ms
```

The latency is **RTT-dominated**, not compute-dominated. The 3.6ms Falcon
signing is negligible. With colocated merchant + facilitator (0ms relay
instead of 68ms), the total drops to ~230ms. With a closer agent↔merchant
link (68ms instead of 114ms), it drops further to ~140ms.

Async settlement: ~7-10s (STARK prove + block inclusion), off the critical path.

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
