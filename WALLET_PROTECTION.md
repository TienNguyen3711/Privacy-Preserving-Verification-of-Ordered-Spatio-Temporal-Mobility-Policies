# Encrypted wallet with an online rollback anchor

The default `wallet_prove` mode encrypts persistent evidence, budget state and
cached receipts in `state.enc`. AES-256-GCM authenticates the snapshot. Each
write draws a fresh 256-bit salt and derives a snapshot key with HKDF-SHA256;
a fixed GCM nonce is used only with that derived key. Keys are private 32-byte
files outside the wallet directory. Serialized plaintext buffers are zeroized;
the loaded trajectory and other working objects still exist in RAM. This is
at-rest encryption, not protection against a compromised process or root.

## Authoritative ledger

`python/zkmob/anchor_service.py` maintains a durable SQLite ledger in a separate
service. It stores only wallet IDs, revisions and encrypted-snapshot hashes,
with an append-only application-level event history. It receives no trajectory,
policy or decryption key. A bearer token authenticates clients. Remote clients
require HTTPS with certificate validation; explicit loopback HTTP is for tests.
The reference server binds loopback and requires a trusted HTTPS reverse proxy
for deployment on an independent host.

Before a transition, the wallet writes and fsyncs an encrypted pending snapshot.
The service atomically compares the old revision/hash and commits the new head.
Only then does the wallet rename and fsync its local snapshot. Opening a wallet
reconciles a pending snapshot against the remote head, either completing an
accepted write or discarding an uncommitted stage. Other mismatches fail closed.
Reservations precede proving; completion precedes receipt release. Cached replies
also require an online head check. No offline fallback or budget refund exists.

Two copies may open the same head, but only one different successor can win CAS.
Restoring a previous folder cannot restore its budget. A current copy may still
return the identical cached response; this does not introduce a new answer.
Wallet identity is a keyed digest of the trajectory: re-enrolling the same trace
under the same master key is rejected even with a new commitment blind.

## Scope and assumptions

- This enforces one state history for honest clients sharing the same trusted
  ledger and identity key. It does not prevent copying bytes or malicious
  software possessing the trajectory/key from bypassing the wallet entirely.
- The ledger must be administered and backed up independently of wallet clients.
  Rolling back or replacing the ledger defeats the guarantee. SQLite durability
  is not hardware anti-rollback. There is no reset/delete API; operators must
  not restore stale ledger backups as authoritative current state.
- A new master key changes wallet identity. Preventing malicious re-enrolment
  under another identity requires authenticated admission, not this prototype.
- The service learns a stable opaque wallet ID, revision history and timing.
  It must be outside the unlinkable verifier view, or that leakage must be
  included in A's side information and simulation premise. Collusion is not
  covered by a claim of verifier unlinkability here.
- Ledger credentials authorize state updates; malicious authorized clients can
  deny service. The ledger does not itself verify budget semantics or proofs.
- HTTPS transport is not asserted to be post-quantum. This change does not close
  the end-to-end PQ composition argument, certified registry admission,
  authenticated verifier identities, or joint adaptive simulation.
- Losing the key, authoritative ledger state or latest committed snapshot may
  make the wallet unavailable. The wallet reports an error rather than resetting
  spent budget.

## Usage

From `code/zkvm`, build `cargo build --offline --release -p host --bin wallet_prove`.
Create existing private parent directories first. Generate separate credentials:

```sh
target/release/wallet_prove --generate-key /private/path/wallet.key
target/release/wallet_prove --generate-key /private/path/ledger.token
```

On the independent service host (provision the token securely):

```sh
python3 python/zkmob/anchor_service.py --init --state-dir /private/path/ledger
python3 python/zkmob/anchor_service.py --state-dir /private/path/ledger \
  --token-file /private/path/ledger.token --port 8765
```

Expose that loopback service through a trusted HTTPS reverse proxy. On the client,
pass these options on both initialization and every query:

```sh
--key-file /private/path/wallet.key \
--anchor-url https://ledger.example.org \
--anchor-token /private/path/ledger.token
```

Initialization also requires `--latency-ms <ms>` (> 0, fixed for the
wallet's life; see WALLET_STORAGE.md). The real-prover smoke test
(`python3 python/benchmarks/protected_wallet_smoke.py`) checks that fresh yes
and no answers are released at 45 s, and that a 1 s wallet expires requests,
never releases them, does not refund them, and records two ledger commits per
expired request. The initialization, policy and request options are described in
[WALLET_STORAGE.md](WALLET_STORAGE.md). For local integration only, use
`--anchor-url http://127.0.0.1:8765 --allow-loopback-http`.

Existing `state.json` wallets are not automatically migrated. The historical
plaintext mode now requires `--legacy-plaintext`; it has no anti-rollback
protection. Never recreate an existing spent wallet to obtain a fresh cap.

## Validation

`cargo test --offline --release -p host --test vault_anchor --test wallet_storage`
passes 15 tests: authenticated encryption, wrong keys/tokens, tampering, stale
copies, concurrent CAS, restart/cache/cap, interrupted commits, offline rejection,
permissions and process concurrency. Storage tests use opaque receipt bytes.

`python3 python/benchmarks/protected_wallet_smoke.py` runs the real STARK prover
and a separate local ledger process, then checks cached receipt equality, stale
clone rejection, budget exhaustion and offline rejection. Public results are
written to `results/wallet_protection_smoke.json`; private artifacts stay under
`work/`. This is an integration test, not production deployment or a security audit.

Recorded smoke result: one real 224,066-byte STARK receipt in 23.84 seconds;
byte-identical cached retry after restart in 0.020 seconds. All six checks passed.
These are single-run functional timings, not a performance benchmark.

## Commit crash injection and protected either-outcome checks

Run subprocess crash tests explicitly with:

```sh
cargo test --offline --release -p host --features fault-injection \
  --test vault_anchor --test wallet_storage
```

The optional `fault-injection` feature enables `ZKMOB_COMMIT_FAULT` hooks;
normal builds do not activate them. Child processes abort without unwinding
at `staged`, `anchored`, `renamed`, and `synced`, for both reservation and
response completion (eight crash scenarios). Recovery checks the persisted
counter before retry, the response cache, the original slot, and exhaustion.
An uncommitted reservation may be discarded because no answer was released;
an anchored reservation must remain spent. These are process-crash tests,
not physical power-loss or storage-controller durability tests.

The protected smoke script now proves both yes and no, retries both after
restart, and explicitly asserts zero stdout bytes on every expected failure
(stale clone, changed-policy retry, and unavailable ledger with cached receipt).
Build the normal binary without `--features fault-injection` for this smoke
and deployment. Timings in the result JSON are single-run observations.

Latest expanded validation: 17 passing test entries including subprocess
helpers; eight actual SIGABRT scenarios. Protected yes/no proving took
26.40/27.25 seconds, respectively. All smoke checks, including empty failure
stdout and both cached retries, passed.

## Additional ledger/network integration scenarios

The default `vault_anchor` suite also exercises:

- Hard-kill and restart of the actual ledger process with the same database,
  preserving a completed response and a pending reservation at exhaustion.
- Twelve separately opened wallet directories competing concurrently: exactly
  one clone advances the shared history, and its remaining budget stays bounded.
- A loopback proxy that forwards a commit to the real ledger, consumes its
  successful response, then drops the client connection. Both reservation and
  completion are tested. The client fails and poisons its handle; after a hard
  ledger restart, reopening reconciles the exact encrypted pending snapshot,
  preserves its slot/cache, and still enforces exhaustion.

These tests use opaque response bytes, not twelve concurrent STARK proofs.
They do not exercise a remote production deployment or physical power loss.

## Model, storage faults and metadata observations

`seeded_state_machine_matches_reference_across_restarts` uses four fixed seeds,
120 operations per seed and three verifier scopes. A separate map models slot
allocation, cached completion, exhaustion and rejected changes. After every
operation the decrypted persisted counters, slots and responses are compared
against the model; wallet reopen and ledger restart are interleaved. This is
bounded deterministic model-based testing, not exhaustive model checking.

`protected_storage_failure_poisoning_and_truncated_snapshots_fail_closed`
causes a real staging-path filesystem error during reserve and complete, checks
handle poisoning and preservation of the committed snapshot, then tests empty,
short-header and truncated-tag snapshots. Reopening rejects corrupted state;
restoring the exact current ciphertext preserves the budget. This does not
simulate ENOSPC, failed fsync, controller write reordering or power loss.

The real-prover smoke exports `results/wallet_metadata_observations.json`.
It measures ledger event counts/revisions and distinct wallet identities, plus
client call duration, stdout length and encrypted snapshot size. These observer
views must not be conflated: local snapshot sizes are not sent to the ledger,
and client elapsed time is not a recorded ledger request timestamp. The ledger
can link commits through a stable identity; each fresh completed answer adds
two commits whereas cached retries add none. The ledger can also observe reads,
although its event table does not record them. These observations expose an
explicit privacy boundary, not a privacy test that the system has passed.
One yes/no pair cannot establish outcome distinguishability, mutual information
or the absence of a timing side channel; that requires repeated controlled runs.

## Update (3 October 2026)

The wallet is now per device (version 5, see WALLET_STORAGE.md). The anchor
identifier is derived from the device's budget tag, so all traces of a device
share one ledger chain. `global_registry_smoke.py` now runs one wallet per
device with `--add-trace`; result: one root, distinct nullifiers, 0 linked
pairs among 10 presentations, and the device budget is shared by its trips.
