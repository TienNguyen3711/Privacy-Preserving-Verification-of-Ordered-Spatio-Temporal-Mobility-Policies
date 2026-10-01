# Persistent wallet and setup separation

The storage mechanics below describe the historical plaintext mode. The CLI
now defaults to encrypted storage with an online ledger: see
[WALLET_PROTECTION.md](WALLET_PROTECTION.md). These historical commands require
`--legacy-plaintext`; protected use requires key and ledger options.

The new `zkvm/host/src/wallet.rs` stores the signed trace, its original blind,
registry path, immutable budget, reservations and completed receipt bytes
on the local filesystem. RAM is only a working copy; restart reloads the
authoritative disk snapshot. Existing Groth16 `SlotWallet` remains a RAM-only
benchmark helper. The new executable is `wallet_prove` in the zkVM workspace.

## Storage and transaction behaviour

- Unix directory mode 0700, files 0600. Storage is **not encrypted**; the
  owner/root can read the trajectory and signing evidence. Put it on an
  appropriately protected local disk. Receipt JSON byte arrays trade space
  for simplicity; this prototype rewrites the snapshot on each transition.
- An OS exclusive file lock is held through admission, proving, completion
  and output. Other processes wait; process death automatically releases the
  lock. Throughput is intentionally serial for one wallet, even across V.
- A snapshot is written to `state.pending`, flushed with `sync_all`, renamed
  atomically to `state.json`, then the wallet directory is flushed. Creation
  also flushes the parent directory. Requires local filesystem lock/rename/
  fsync semantics; network filesystems are not supported by this guarantee.
- Reservations are persisted BEFORE computing the outcome or generating a
  proof. Both yes and no spend a slot; failed proving/output is never refunded.
- Request IDs are scoped to a verifier and bound to the complete typed
  Statement (policy, R, V and frozen B). A changed statement for the same ID
  is rejected. An identical pending request resumes the same slot; a completed
  request returns the same saved bytes, including after budget exhaustion.
- Receipts are verified and checked against the reserved witness/journal,
  then persisted BEFORE stdout release. Cached receipts are verified again.
- Storage errors poison the in-memory wallet so it cannot subsequently
  return an unpersisted reservation/response as successful. Close and recover
  the on-disk state before further work.
- Opening missing, malformed or inconsistent state fails closed. Initialising
  an existing directory fails, including after an interrupted initialisation.
  Never delete a damaged wallet merely to restore budget: investigate/recover
  its original state or treat it as permanently unavailable.

This handles ordinary process restart, concurrent local processes and lost
responses. It does **not** prevent rollback to an old disk backup, cloning
the directory to another machine, re-enrolling the same trace elsewhere or
an owner modifying the files. Those require a single authoritative store
with rollback protection (e.g. a trusted monotonic service) or a stronger
trust model. The confidentiality theorem assumes an honest wallet owner.

## Setup paths

`setup_fixture` is explicitly deterministic and is used by rejection tests
and the profiling binary. Its secrets are public fixtures. The existing
`host` benchmark now defaults to `setup_randomized_local`; pass `--fixture`
to reproduce the old deterministic fixture (prints a warning).

`setup_randomized_local` draws a fresh 32-byte epoch seed and 32-byte blind
from `/dev/urandom`, failing on entropy errors. It signs one trace once and
returns its private evidence. The durable wallet saves that evidence at
initialisation and never regenerates it on reopen. The epoch seed is not
saved because this path signs only one trace; a shared long-lived device
epoch would need its own persistent one-time-key state.

The randomized path constructs a LOCAL registry, including synthetic other
leaves. It does not run manufacturer certification or ML-DSA registry
admission. Fresh entropy removes the known-fixture dictionary attack but is
not a complete authenticated deployment setup or adaptive PQ simulation
proof. The blind is 256 bits (since wallet format v2) because a 128-bit blind
gives only about q_H 2^-64 against quantum hash queries (paper, App. D).
Older wallets (v1: 16-byte blind; v2: no durable deadline) are rejected, not migrated. No numerical
security level for the whole composition is asserted.

## Commands

Requires Unix and Rust >=1.89 (`std::fs::File::lock`). From `code/zkvm`:

```sh
cargo build --offline --release -p host --bin wallet_prove

# Parent directory must already exist; wallet directory must not exist.
target/release/wallet_prove --legacy-plaintext --init --wallet ../work/my_wallet \
  --traces ../work/n1_geolife.jsonl --n 128 --budget 2 --latency-ms 0

# Policy JSON has the zkVM Policy fields: {"steps":[...],"avoid":null}.
# Example identity below is a LOCAL TEST ID, not proof of authentication.
target/release/wallet_prove --legacy-plaintext --wallet ../work/my_wallet \
  --policy ../work/demo_geolife_policy.json --request-id request-001 \
  --verifier 0000000000000000000000000000000000000000000000000000000000000001 \
  > ../work/receipt-001.bin
```

`--latency-ms` is required at `--init` and fixed for the wallet's life
(passing it later is an error). Protected wallets require a value > 0.
Receipts (wallet format v4): each stored receipt is a separate file
`receipts/<sha256>.bin` (AES-256-GCM in protected wallets), written and
fsynced before the state that references its hash is committed; a missing or
altered receipt fails closed. Before v4 every receipt was a JSON number array
inside the state, so each request re-read and re-wrote all stored receipts
(4.2 s per cached retry after 17 receipts, and growing proving-to-release
overhead); the regression test `request_cost_does_not_grow_with_stored_receipts`
covers this.

Release semantics (since wallet format v3, revised 1 Oct 2026 after review R1/R2):

* The reservation durably records `deadline_ms` = admission + latency (Unix
  ms, trusted local clock). A resumed request keeps its original deadline.
* Proving runs in a worker process (`wallet_prove --prove-worker`, statement
  and witness on stdin) in its own process group; the r0vm prover it starts
  is in the same group. Its stdout is a pipe to the wallet and its stderr is
  /dev/null, so nothing reaches the caller.
* Proof not ready at the deadline: the prover group is killed (no orphaned
  prover keeps computing), one `expire` commit, `expired` printed and end of
  output at the deadline; the slot stays spent and no receipt is ever
  released (also on retry).
* Proof ready: wait for the deadline, then commit `complete`, re-check the
  anchor and release. `complete` is refused before the deadline, so a stored
  response never exists early and a retry after a crash cannot release early.
* Either way a fresh request costs two ledger commits: reserve at admission
  and complete/expire at the deadline. Completed requests cannot expire.

Power loss (simulated, `host/tests/power_loss.rs`): a pending snapshot that is
empty or torn was never committed (the ledger CAS follows its fsync), so on
reopen it is discarded if `state.enc` is exactly the ledger tip; a committed
pending snapshot is renamed into place. All 11 enumerated crash states
recover with the ledger's budget, and rollback to an older snapshot fails
closed (`results/power_loss_model.txt`). Not a physical power cut; storage
that ignores F_FULLFSYNC is out of scope.

Request IDs are holder-chosen session names: fresh per session, reused only
to resume that session. Do not forward a verifier-chosen identifier; a cached
retry returns the identical proof and nullifier, so a verifier reusing an
identifier across sessions would link them (re-review F2).

Global registry (`registry` binary, `host/src/registry.rs`): a manufacturer
ML-DSA key certifies device keys; devices sign (epoch, epoch root); the
registry checks both and publishes one Merkle root for all devices. Initialise
with `--device dev.secret --registry registry.json [--trace-index k]`. Leaf
allocation holds an exclusive lock on `dev.lock` across read, signing and the
durable counter write (unique staging files), so concurrent initialisations
never reuse a one-time key (`tests/registry_cli.rs`: 16 enrolments, 8 of them
concurrent, 16 distinct leaves). Restoring an old copy of the device file
would roll the counter back; that is outside the wallet ledger's protection.
The LOCAL test registry (root identifies the wallet) must be requested
explicitly with `--local-registry`; a partial `--device`/`--registry` pair is
rejected before anything is created.

Choose the latency well above the observed proving time (23–33 s for n=32 on
an M-series Mac; the smoke test uses 45 s). `0` (no fixed latency) is
accepted only with `--legacy-plaintext`. Policies are checked against the
full supported domain (`zkmob_core::validate_policy`: 1–8 steps, no gap on
the first step, well-formed zones) before any slot is reserved.

Repeat the same request ID and policy to recover the identical saved receipt.
Use a new ID for a new query. After the cap, a new request returns the public
`exhausted` status. Input trace and cap options are accepted only with --init.
Do not set `RISC0_DEV_MODE`; the executable rejects it.

The CLI takes a verifier digest supplied by an already trusted caller; it
does NOT authenticate remote identities. Allowing an untrusted caller to
choose arbitrary digests permits Sybil budgets. The output is a local CLI
interface, not a network framing protocol. Release time of fresh answers is
fixed (see above), but error strings and network traffic are not
padded/simulated, so A4/A5 remain conditional for network deployment.
All sessions for a wallet/verifier must be included in A's scope.

## Tests and remaining premises

`cargo test --offline --release -p host --test wallet_storage` exercises
restart, pending reservations, cached replies, immutable cap/context,
both outcomes, separate V scopes, 12 concurrent processes, abrupt exits,
corrupt/missing state, storage failure poisoning, file permissions and fresh
randomness. Storage tests use opaque bytes; `wallet_prove` performs actual
receipt verification. Existing guest rejection tests remain separate.

The operational state machine is now implemented for the local proving
path. A's joint adaptive simulation, authenticated V/registry admission,
network metadata behaviour and rollback/clone protection remain explicit
obligations; persistent storage alone does not discharge them.

## Recorded end-to-end check

`python3 python/benchmarks/wallet_smoke.py` (from `code/`) creates a fresh
private wallet under `work/`, then invokes a NEW process for every operation.
The recorded run produced and verified two real succinct STARK receipts
(yes and no, 224,066 bytes each), with proving calls taking 23.43 s and
24.89 s. Restarted retries returned byte-identical persisted receipts in
0.25–0.48 s. Exhaustion, changed-policy retry, cap increase and reinitialisation
checks passed. These are single-run functional timings, not a performance
benchmark. See [wallet_storage_smoke.json](results/wallet_storage_smoke.json).

The process-lock/storage suite has 7 passing tests, including its subprocess
helper; the existing guest rejection test and 41 Python tests also pass. The proving executor
requires permission to launch its local runtime; sandboxed runs on this
machine initially returned `Operation not permitted` and were rerun with
execution permission. No fake/dev-mode receipts were used.
