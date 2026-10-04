# zkmob — Paper 3 codebase

Zero-knowledge verification of ordered spatio-temporal mobility policies over
device-attested trajectories, with a post-quantum composition as the target.
The code exists to test the novelty claims (see the Novelty & Capability
Matrix); it is not yet the final system.

**N5 direction: A as the main conditional theorem, B as supporting analysis.**
`python/zkmob/disclosure.py` computes the ideal guessing bound and optimal
adaptive disclosure for a finite policy pool, including nonuniform priors.
`python/zkmob/n5_capacity.py` compares nested mobility-policy families and
exports CSV results with replayable trees. See [N5_DISCLOSURE.md](N5_DISCLOSURE.md)
for commands, assumptions, attribution and the remaining protocol proof work.
These calculations do not establish cryptographic simulation or wallet-side
budget enforcement.

The precise conditional theorem, wallet lifecycle, QPT scope and current
premise gaps are documented in [A_PREMISES.md](A_PREMISES.md). A new disk-backed
zkVM wallet persists reservations and verified receipts across restarts:
see [WALLET_STORAGE.md](WALLET_STORAGE.md). It uses fresh OS entropy by default;
deterministic setup is explicitly named `setup_fixture`. The old Groth16
wallet is still RAM-only. Certified registry admission, authenticated verifier
identities and adaptive simulation remain separate
deployment obligations. Encrypted snapshots and online CAS rollback/clone
protection are implemented for a trusted independent ledger; see
[WALLET_PROTECTION.md](WALLET_PROTECTION.md) for deployment assumptions and tests.

| Part | Claim / baseline it serves | Status |
|---|---|---|
| `rust/.../src/ordered.rs` | Our design, claim **N1** (order + relative time) | Working, tested, Groth16 end-to-end, exact cost formula |
| `rust/.../src/automaton.rs` | Baseline **B3** (discretise + DFA, Reef / zkreg style) | Working, 4-symbol DFA (overlapping zones), exact cost formula |
| `rust/.../src/commit.rs` | Binding (B2) or **hiding** commitment to the signed trace | Poseidon(r ‖ T) with 128-bit blinding |
| `rust/.../src/io.rs`, `bin/prove_json.rs` | Python → JSON → Rust bridge | Proves policies on real traces |
| `rust/.../bin/n1_real.rs` | N1 on real data | `results/n1_real_*.csv` |
| `rust/.../bin/pilot_n1.rs` | N1 pilot (synthetic) | `results/pilot_n1.csv` |
| `rust/.../src/sig.rs` | Device signatures: B2 (ECDSA / ML-DSA-65); Lamport-Poseidon one-time keys in per-epoch subtrees; device ML-DSA identity; registry of ML-DSA-certified epoch roots; gadgets | Working, tested |
| `rust/.../src/budget.rs` | N5 mechanism: scan circuit (proves yes **or** no exactly) + per-verifier nullifier budget | Working, tested |
| `rust/.../bin/budget_demo.rs`, `keygen_bench.rs` | Budget protocol on a real trace; provisioning cost | `results/n5_budget_protocol.csv`, `n5_scan_cost.csv`, `keygen_bench.csv` |
| `rust/.../src/sigbench.rs`, `bin/sig_bench.rs` | Hidden-signature microbenchmark: Lamport vs WOTS (w = 4, 16, tweaked) × Poseidon width | `results/sig_bench.csv` |
| `python/zkmob/slh_dsa_estimate.py` | In-circuit cost estimate for SLH-DSA (FIPS 205) | `results/slh_dsa_estimate.csv` |
| `zkvm/` (RISC Zero 3.0.6) | **Step 7a: end-to-end PQ, zero-knowledge proof** of the budgeted, unlinkable relation (SHA-256 instantiation) | Working, tested; `results/zkvm_budget.csv` |
| `stark/` (Plonky3, pinned commit) | **Step 7b: hand-written ZK STARK components**: policy scan table + Poseidon2 hash workload | Scan working and tested; tables not yet linked; `results/stark_bench.csv` |
| `python/zkmob/n5_bounds.py` | N5 formal model on real data: leakage vs charging rule (exact) and per-person leakage over K traces | `results/n5_bounds_charging.csv`, `n5_bounds_users.csv` |
| `python/zkmob/n5_budget.py` | Anonymity set vs budget B, charging all answers vs yes-only | `results/n5_budget.csv` |
| `rust/.../src/unlinkable.rs` | Unlinkable proof, claim **N4** (C, signature, device key all private) | Working, tested (5 forgery cases rejected) |
| `rust/.../bin/n4_link.rs` | N4 experiment: linkability, size and cost of B2 vs unlinkable | `results/n4_linkability*.csv` |
| `python/zkmob/policy.py` | Reference semantics (ground truth for every circuit) | Working, tested |
| `python/zkmob/datasets.py` | GeoLife / T-Drive / Porto loaders, cleaning, time split | Working, tested on fixtures and real files |
| `python/zkmob/bridge.py` | Policy language → circuit policy; runs the prover | Working, tested |
| `python/zkmob/n1_export.py`, `n1_report.py` | N1 real-data workload and summary | `results/n1_real_summary.csv` |
| `python/zkmob/leakage.py` | Baseline **B5**, claim **N5** (synthetic) | `results/b5_leakage.csv` |
| `python/zkmob/n5_real.py` | N5 on real data (time-split) | `results/n5_real.csv` |

Groth16 over BN254 provides the classical baseline and exact constraint counts.
The RISC Zero implementation below proves the full relation with a STARK;
the end-to-end quantum-security composition argument remains unfinished.

## Layout

```
code/
├── data/                     raw datasets (not redistributed; see below)
├── work/                     generated JSON/JSONL inputs (git-ignored)
├── results/                  experiment outputs (CSV)
├── python/
│   ├── zkmob/                trajectory, policy, datasets, bridge, experiments
│   └── tests/                unittest suite (numpy only)
└── rust/zkmob-circuits/
    ├── src/
    │   ├── types.rs          Point, BoxZone, Step, native witness search
    │   ├── gadgets.rs        range check, <=, box membership, one-hot select
    │   ├── commit.rs         Poseidon commitment: off / binding / hiding
    │   ├── ordered.rs        our circuit + ours_constraints()
    │   ├── automaton.rs      B3 circuit, resampling, native DFA, b3_constraints()
    │   ├── io.rs             JSON formats shared with Python
    │   ├── sig.rs            ECDSA / ML-DSA / Lamport-Poseidon, Merkle, registry
    │   ├── unlinkable.rs     unlinkable circuit (policy || registry root public)
    │   ├── budget.rs         scan circuit, budgeted circuit, nullifier log, slot wallet
    │   ├── scenario.rs       deterministic synthetic scenario
    │   └── bin/              pilot_n1, prove_json, n1_real, n4_link, budget_demo, keygen_bench
    └── tests/
        ├── circuits.rs       soundness / completeness / cost-formula tests + Groth16
        ├── signatures.rs     signatures, epochs, registry, unlinkable circuit, linkability
        └── budget.rs         scan semantics (3,000 random cases), both outcomes, slots, nullifiers
```

Datasets expected under `data/`: `Geolife Trajectories 1.3/Data/…`,
`T-drive Taxi Trajectories/taxi_log_2008_by_id/…`, `porto_taxi/train.csv`.
(Gowalla and the Foursquare TIST2015/UbiComp2016 archives are also there;
they are check-in data, not trajectories, and are not used yet.)

## Post-quantum back ends (step 7)

Both use only hash functions (no pairings, no trusted setup) and run in a
zero-knowledge mode.

**7a. RISC Zero zkVM, end to end** (`zkvm/`). The whole budgeted, unlinkable
relation (`zkvm/core`: hiding commitment, Lamport one-time signature, epoch and
registry Merkle paths, policy scan with yes/no outcome, slot < B, nullifier)
runs as a guest program. Every hash is SHA-256, which the zkVM accelerates.
Poseidon over BN254 would need 254-bit arithmetic on a 32-bit CPU. The
structure is identical to the Groth16 circuit, and Lamport over SHA-256 is a
standard PQ one-time signature. The public output (journal) is policy,
outcome, R, V, B, N. The executor rejects a tampered trace, a wrong blinding
value, a slot ≥ B, a wrong registry root and an unsorted trace (`host/tests`).
Succinct STARK receipts on real GeoLife traces, measured on an Apple Silicon
CPU:

| n (fixes) | Guest cycles | Prove | Verify | Receipt |
|---|---|---|---|---|
| 128 | 386k (1 segment) | 23 s | 9.1 ms | 224 kB |
| 256 | 406k | 23 s | 9.1 ms | 224 kB |
| 512 | 445k | 45 s | 9.1 ms | 224 kB |
| 1024 | 529k | 45 s | 9.1 ms | 224 kB |

Engineering note: the zkVM's default input codec spends one word per byte,
so reading the 16 kB Lamport signature took 90% of cycles (3.46M cycles,
200 s). A compact byte encoding cut this to 386k cycles and 23 s. The relation
itself is about 320k cycles. Proving time follows the padded segment size
(2^19 or 2^20 cycles).

**7b. Plonky3, hand-written AIR** (`stark/`, zero-knowledge `HidingFriPcs`,
BabyBear, Keccak Merkle commitments, `new_benchmark_zk` FRI: blowup 4,
100 queries, 16-bit PoW):

* `ScanAir`: the policy scan as a 259-column table, one row per fix, proving
  either outcome. It is proved and verified on 150 random policies against
  the native relation; the opposite outcome never verifies. Hiding FRI with
  100 queries needs at least 256 rows, so short traces are padded with inactive
  rows, which also hides the exact number of fixes.
* The relation's hash workload as Poseidon2 permutations (width 16):
  commitment + Lamport on a 248-bit digest + 30 Merkle levels + nullifier
  (826 permutations at n = 128).

| n | Scan: prove / verify / proof | Poseidon2 workload: prove / verify / proof | Sum (not linked) |
|---|---|---|---|
| 128 | 15 ms / 1.6 ms / 256 kB | 32 ms / 2.1 ms / 329 kB | 47 ms, 585 kB |
| 512 | 15 ms / 1.4 ms / 284 kB | 28 ms / 2.1 ms / 329 kB | 43 ms, 613 kB |
| 1024 | 31 ms / 1.6 ms / 317 kB | 57 ms / 2.5 ms / 366 kB | 89 ms, 683 kB |

**Not yet done:** the two Plonky3 tables are proven separately. A single
proof of the full relation needs a sponge table that chains Poseidon2 states,
Lamport bit selection and Merkle chaining, linked to the scan table by
cross-table lookups (Plonky3 `batch-stark` + LogUp, which supports ZK). So
the "sum" row is an estimate of the composed proof, not a measurement. The
RISC Zero result is the complete end-to-end PQ proof today.

Comparison at n = 128 for the budgeted, unlinkable relation:

| Back end | PQ | Setup | Prove | Verify | Proof |
|---|---|---|---|---|---|
| Groth16 / BN254 (arkworks) | no | trusted, per circuit | 1.4 s | 1.3 ms | 128 B |
| RISC Zero (STARK, SHA-256) | yes | none | 23 s | 9 ms | 224 kB |
| Plonky3 AIR (STARK, Poseidon2), components | yes | none | ≈ 47 ms | ≈ 4 ms | ≈ 585 kB |

The PQ price is proof size (about 1,700 to 4,600× larger than Groth16), not
necessarily prover time: the hand-written STARK components are about 30× faster
than Groth16, and the zkVM about 16× slower (generality overhead).

## Run it

Requirements: Rust 1.85+ (edition 2024; installed with rustup in `~/.cargo`,
so run `. "$HOME/.cargo/env"` in a new shell) and Python 3.9+ with numpy.

```bash
cd "Paper 3/Codebase/code"
M=rust/zkmob-circuits/Cargo.toml

# tests (24 Rust, 21 Python)
cargo test --release --manifest-path $M
PYTHONPATH=python python3 -m unittest discover -s python/tests -v

# synthetic pilots
cargo run --release --manifest-path $M --bin pilot_n1 -- --prove
PYTHONPATH=python python3 -m zkmob.leakage

# prove a policy on one real trace (hiding commitment, Groth16)
PYTHONPATH=python python3 -m zkmob.bridge --dataset geolife      # or porto / tdrive

# N1 on real data (about 1 minute for all three datasets)
for ds in geolife tdrive porto; do
  PYTHONPATH=python python3 -m zkmob.n1_export --dataset $ds --trips 400
  cargo run --release --manifest-path $M --bin n1_real -- --in work/n1_$ds.jsonl --out results/n1_real_$ds.csv
done
PYTHONPATH=python python3 -m zkmob.n1_report

# N5 on real data (about 40 seconds)
PYTHONPATH=python python3 -m zkmob.n5_real

# N4: B2 (ECDSA, ML-DSA) vs unlinkable, on real GeoLife trips (about 2 minutes;
# needs work/n1_geolife.jsonl from n1_export)
cargo run --release --manifest-path $M --bin n4_link

# N5 mechanism: budget protocol on a real trace, provisioning, budget curves
cargo run --release --manifest-path $M --bin budget_demo
cargo run --release --manifest-path $M --bin keygen_bench
PYTHONPATH=python python3 -m zkmob.n5_budget          # about 40 seconds
# A4 timing: 12 alternating host runs (24 STARK proofs), then the analysis
# (cd zkvm && for i in $(seq 1 12); do ./target/release/host --n 128 --out ../results/a4_timing.csv $([ $((i%2)) -eq 0 ] && echo --reverse); done)
PYTHONPATH=python python3 -m zkmob.a4_timing
PYTHONPATH=python python3 -W ignore -m zkmob.n5_bounds   # about 2 minutes

# step 7a: RISC Zero (install once: curl -L https://risczero.com/install | bash && rzup install)
cd zkvm && cargo test --release && cargo run --release -p host -- --n 128 && cd ..   # never set RISC0_DEV_MODE
# step 7b: Plonky3 components
cd stark && cargo test --release && cargo run --release --bin stark_bench && cd ..

# signature microbenchmark (one process per variant, with peak memory) and SLH-DSA estimate
B=rust/zkmob-circuits/target/release/sig_bench; cargo build --release --manifest-path $M --bin sig_bench
$B --header; for v in lamport_t3 lamport_t9 lamport_t17 wots_w4_t3 wots_w4_t17 wots_w4x_t3 wots_w16_t3 wots_w16_t17; do /usr/bin/time -l $B --variant $v; done
PYTHONPATH=python python3 -m zkmob.slh_dsa_estimate
```

## Conventions that matter for soundness

* Coordinates are planar metres, timestamps are seconds from the start of the
  trip, both integers below 2^32 (`COORD_BITS`, `TIME_BITS`).
* Every value a circuit compares is range-checked first; without that a
  malicious prover could exploit field wrap-around.
* Trajectories are time-sorted; the device (not the prover) guarantees this
  when it signs. Our circuit still checks time order between selected points.
* The Python `policy.evaluate` is the specification. Any new circuit must get
  a test that compares it with `evaluate`; `n1_real` also re-checks Rust
  against Python on every real-data item (0 mismatches so far).
* The hiding commitment's blinding value must be fresh per trace
  (`prove_json` reads it from `/dev/urandom`). Hiding does **not** make proofs
  unlinkable: all proofs about one trace still show the same C. Only the
  `Unlinkable` design (C in the witness) is unlinkable.
* Device keys are **stateful**: each Lamport one-time key signs exactly one
  trace commitment (`EpochKey::sign` only moves forward). Reusing a leaf
  would allow forgeries. Epoch numbers are strictly increasing and checked
  by the registry.
* Budget assumptions: the verifier id V is authenticated (otherwise Sybil
  verifiers each get B answers); the device commits to each trace exactly
  once (a fresh r would reset the budget); the nullifier has no epoch, so
  the budget never resets.

## Real-data preprocessing (`datasets.py`)

Equirectangular projection around a fixed city origin (Beijing for GeoLife and
T-Drive, Porto), window of ±30 km / ±15 km. Fixes implying > 60 m/s and
duplicate timestamps are dropped; trips are cut at gaps (GeoLife 600 s,
T-Drive 900 s, Porto: one row = one trip) and at 2 h, and must have ≥ 20
fixes (T-Drive ≥ 10) and ≥ 10 min (Porto ≥ 5 min).

| Dataset | Median sampling | Median fixes / trip | Median duration |
|---|---|---|---|
| GeoLife | 4.6 s | 437 | 28 min |
| Porto | 15 s | 43 | 10.5 min |
| T-Drive | 300 s | 24 | 1.9 h |

## Results

### N1 pilot (synthetic): cost versus time precision

One-hour drive, GPS every 5 s (n = 720), policy "visit A, then B within
900 s". B3 resamples into buckets of width w and runs a DFA with k + 2 states,
k = ceil(900 / w), over 4 symbols (A only, B only, both, other).

| Design | Time precision | Policy constraints | Correct outcome? | Groth16 prove |
|---|---|---|---|---|
| Ours | 1 s (exact) | **6,301** | yes | 0.07 s |
| Ours + hiding commitment | 1 s | 268,982 | yes | 2.0 s |
| B3 | 600 s | 2,181 | **no** | – |
| B3 | 300 s | 4,433 | **no** | – |
| B3 | 180 s | 7,593 | yes | – |
| B3 | 60 s | 25,793 | yes | ✓ |
| B3 | 15 s | 157,193 | yes | ✓ |
| B3 | 5 s | 903,593 | yes | – |

Both costs have exact closed forms, checked against synthesis in
`cost_formulas_match_synthesis`:

* ours: s(232 + 4n) + (s − 1)(bits(n) + 34) + 33·(gapped steps)
* B3: (349 + k) + (L − 1)(356 + 5k), with L = T / w

Caveats that still hold: (1) the commitment (~262k constraints at n = 720)
dominates the policy part, and any fair B3 must bind to the same signed trace
too; (2) B3 is plain R1CS, pessimistic versus Reef's lookup arguments, but
L = T / w still grows with precision.

### N1 on real traces

400 trips per dataset × 4 policies = 1,600 policies per dataset
("A then B within Δ", zones of half-side 50 to 200 m anchored on the trip;
`tight` Δ = 0.8 to 1.25 × the observed gap, `loose` Δ ∈ {5, 10, 15, 30} min,
`reversed` tests order). Outcome is computed exactly and matches Python on
all 4,800 items. B3 is evaluated with two discretisations: **any-fix** (a
bucket is in A if any fix in it is; best case for B3) and **carry-forward**
(what the B3 circuit computes).

B3 error rate (any-fix) and median B3/ours constraint ratio:

| w | GeoLife | Porto | T-Drive |
|---|---|---|---|
| 300 s | 14.2% · 0.61× | 31.4% · 1.10× | 12.4% · 11.9× |
| 120 s | 5.9% · 1.48× | 11.2% · 2.46× | 8.1% · 31× |
| 60 s | 3.4% · 3.1× | 6.9% · 4.8× | 5.2% · 66× |
| 15 s | 1.5% · 16× | 2.8% · 22× | 1.1% · 394× |
| 5 s | 0.6% · 77× | 0.6% · 90× | 0.5% · 2,261× |

Carry-forward B3 is much worse (for example 16 to 32% error at 60 s on
GeoLife / Porto, and a floor of about 11% on T-Drive at any w, because
sparse fixes are carried across zone boundaries).

What this shows: at widths where B3 is no more expensive than our circuit
(median ratio ≤ 1: GeoLife w ≥ 180 s, Porto w = 600 s; never on T-Drive), it
gets 8 to 55% of real policies wrong. To get below 1% error it needs
w ≤ 10 s (5 s on Porto), costing 28 to 720× more constraints. The time width must be fixed at circuit
setup, before the data is seen, so this whole-workload error rate is the
relevant measure. Errors are mostly false negatives at coarse w (true
statements cannot be proven) and false positives at fine w (a false
statement gets proven, which is a soundness failure with respect to the
policy). For T-Drive (sparse, long trips) the ratio is extreme because our
cost scales with fixes and B3 with duration / w.

### N5 on real data (time split)

Candidates: evaluation-period trips (last 30% by start time); query zones
uniform, or drawn by popularity in the history period (first 70%). 40
trials per setting, pool of 600 queries, adaptive = greedy halving.

| Scope | Candidates | Pool | Adaptive: identified after 10 / 20 queries (250 m / 1 km zones) |
|---|---|---|---|
| Porto, city-wide | 2,000 | popular | 28% / 70% · 25% / 88% |
| Porto, city-wide | 2,000 | uniform | 12% / 25% · 10% / 78% |
| GeoLife, 6 users (own trips) | 80–670 | popular | 32–90% after 10 queries |
| GeoLife, 6 users (own trips) | 80–670 | uniform | 0–35% after 10 queries |

Random (non-adaptive) queries identify almost nobody within 40 queries. So
the leakage comes from a verifier that *chooses* queries adaptively using
historical popularity. This supports a query budget or accountant as the
mitigation; making zones larger does not help (1 km zones leak as much as, or
more than, 250 m zones).

### N4: linkability of signed-trace proofs (step 6)

Four ways to bind a policy proof to a device-signed trace. In the three B2
designs (Bogdanov et al. 2025 style), the verifier checks the signature on C
outside the circuit. In the **unlinkable** design (instantiation (c)), the
device signs C = Poseidon(r ‖ T) with a Lamport one-time key over Poseidon.
Its one-time keys form small per-epoch Merkle subtrees. Each epoch root is
signed by the device's ML-DSA-65 key (itself certified by the manufacturer)
and admitted to a public registry, all checked outside the circuit. The proof
shows only the policy and the registry root R; C, the signature, the epoch
root and both Merkle paths are witnesses.

Setup: 4 devices × 3 real GeoLife trips (first 128 fixes) × 3 true policies =
36 presentations per design, 630 pairs. A pair is *linked* if the two
presentations share any value that is not common to all presentations.

| Design | Constraints | Prove | Verify | Presentation | Linked: same trip | same device | other device |
|---|---|---|---|---|---|---|---|
| B2-ECDSA (binding C) | 48,217 | 0.37 s | 1.3 ms | 257 B | 100% | 100% | 0% |
| B2-ML-DSA-65 (binding C) | 48,217 | 0.37 s | 1.3 ms | 5,421 B | 100% | 100% | 0% |
| B2-ML-DSA-65 (hiding C) | 48,460 | 0.37 s | 1.2 ms | 5,421 B | 100% | 100% | 0% |
| **Unlinkable** | 182,391 | 1.32 s | 1.3 ms | **128 B** | **0%** | **0%** | 0% |

Unlinkable circuit breakdown (n = 128, device tree depth 6, registry depth
16): policy 1,563 + commitment 46,897 + Lamport verification 123,305 + Merkle
10,626 (483 per level × 22 levels). Registration costs one ML-DSA-65
verification (1.1 ms, 3,309 B certificate) per device, not per proof.

What this shows:

1. **B2 is linkable by construction**, with either signature scheme: the
   commitment C links every proof about one trip, and the device key links
   every trip of one device. Hiding C (blinding r) changes nothing, because C
   is still shown. Swapping ECDSA for ML-DSA makes B2 post-quantum but
   21× larger (5.4 kB per presentation), and it stays exactly as linkable.
2. **The unlinkable design shares nothing but R** across all devices'
   proofs. It is also *smaller* than both B2 variants (just the proof), at
   3.5× the proving cost of B2. Against the equality test used here it is
   perfectly unlinkable; in general it is unlinkable because Groth16 is
   zero-knowledge (a formal game is still to be written). What remains is
   what the policies and outcomes reveal (N5).
3. **Where the cost goes:** Lamport verification (68%) dominates. WOTS+ is
   predicted to help little in-circuit (w = 4: about 5 to 9%; w = 16: about 2×
   worse), so this still needs a benchmark, together with a wider Poseidon.
   Provisioning is solved separately (see below).

### N5 formal model: leakage bounds checked on real data (`n5_bounds`)

Leakage is measured as Shannon leakage I(T;V) (mean, 95% CI) and min-entropy
leakage log2(M·E[1/A]) (Smith 2009), next to the effective anonymity set
2^{H(T|V)} (Serjantov and Danezis 2002). A deterministic adaptive verifier sees
at most as many transcripts as there are answer strings, which gives a
**lemma on charging rules** (valid for any prior and both metrics):

* every answer charged (proofs of yes **and** no): L ≤ B, independent of the
  number of queries Q;
* only "yes" charged (proofs of yes only): L ≤ log2 Σ_{i≤B} C(Q, i) ≈
  B·log2(eQ/B), which grows with Q.

**Experiment A (exact).** For a uniform prior over M = 2,000 trips the verifier's
decision tree is enumerated for every possible target (no sampling). Best
attacker, Shannon / min-entropy bits (bound):

| Charging | B = 1 | B = 2 | B = 4 | B = 8 |
|---|---|---|---|---|
| Porto, every answer | 0.7 / **1.0** (≤ 1) | 1.4 / **2.0** (≤ 2) | 2.8 / **4.0** (≤ 4) | 5.9 / **8.0** (≤ 8) |
| Porto, "yes" only, Q = 20 | 3.8 / **4.4** (≤ 4.4) | 5.5 / 7.1 (≤ 7.7) | 8.4 / 9.7 (≤ 12.6) | 9.6 / 10.6 (≤ 18.0) |
| Porto, "yes" only, Q = 100 | 1.9 / **6.7** (≤ 6.7) | 2.2 / 8.3 (≤ 12.3) | 9.3 / 10.0 (≤ 22.0) | 10.6 / 10.8 (≤ 37.6) |
| Porto, "yes" only, Q = 300 | 7.4 / 7.9 (≤ 8.2) | 10.5 / 10.7 (≤ 15.5) | 10.6 / 10.8 (≤ 28.3) | 10.6 / 10.8 (≤ 50.4) |

(GeoLife gives the same pattern; see the CSV.) Both bounds hold in all 108
settings and are **tight**: min-entropy equals B exactly when every answer is
charged, and reaches log2(1 + Q) at B = 1 when only "yes" is charged. With a
budget of one answer, leakage is 1 bit if "no" is proven and 4.4 to 7.9 bits
(20 to 300 queries) if it is not. Leakage saturates at log2 M ≈ 11 bits.

**Experiment B (per-person leakage over K traces, Monte Carlo, 40 trials).** The
secret is the person (398 Porto taxis, 24 GeoLife users); the verifier gets B
answers on each of K traces of that person and keeps a Bayesian posterior over
people (non-uniform, so A_eff differs from a count). Chain rule: I(U;V) ≤ K·B.

| Scope | B | K = 1 | K = 2 | K = 4 | K = 8 |
|---|---|---|---|---|---|
| GeoLife (24 users) | 2 | 0.77 bits, top-1 18% | 0.66, 10% | 1.82, 35% | 2.54, 55% |
| GeoLife (24 users) | 4 | 0.95, 12% | 2.03, 40% | 2.33, 45% | 3.92, 85% |
| Porto (398 taxis) | 4 | 0.58, 2% | 1.04, 5% | 2.23, 2% | 4.89, 52% |

All 24 settings are within K·B. **A per-trace budget does not bound leakage
about the person:** with B = 4 per trace, eight traces identify a GeoLife user
85% of the time and a Porto taxi 52% of the time. The budget scope must be the
device (or epoch key) if per-person leakage matters (review W3).

### Which hidden signature? (microbenchmark, `sig_bench`)

Same workload for every variant: verify a one-time signature on the 254-bit
C inside a Groth16 circuit (public: public-key hash). Median of 3 proofs;
peak memory from a separate process per variant.

| Variant | Constraints | Synthesis | Prove | Signature | Keygen / key | Peak RAM |
|---|---|---|---|---|---|---|
| **Lamport, t = 3 (current)** | **123,306** | 0.51 s | **0.90 s** | 16.3 kB | 15.2 ms | 1.3 GB |
| Lamport, t = 9 compression | 87,261 | 0.99 s | 1.27 s | 16.3 kB | 15.7 ms | 1.2 GB |
| Lamport, t = 17 compression | 80,925 | 1.93 s | 2.19 s | 16.3 kB | 20.0 ms | 1.3 GB |
| WOTS w = 4 (untweaked) | 112,759 | 0.47 s | 0.83 s | 4.2 kB | 8.3 ms | 1.2 GB |
| WOTS w = 4 + t = 17 | 101,986 | 0.88 s | 1.20 s | 4.2 kB | 10.1 ms | 1.2 GB |
| WOTS+ w = 4 (tweaked) | 132,955 | 1.28 s | 1.67 s | 4.2 kB | 16.0 ms | 1.8 GB |
| WOTS w = 16 | 254,130 | 1.06 s | 1.76 s | 2.1 kB | 18.4 ms | 2.7 GB |
| WOTS w = 16 + t = 17 | 248,928 | 1.30 s | 1.99 s | 2.1 kB | 19.3 ms | 2.7 GB |

What this shows:

1. **Keep Lamport; the WOTS branch is closed.** w = 16 is 2× worse. Untweaked
   w = 4 is only 9% smaller and 8% faster, and its standard security proof
   needs address-bound (tweaked) chains. The tweaked WOTS+ is *worse* than
   Lamport (+8% constraints, 1.9× prove time). Lamport's own security needs
   only a one-way hash. WOTS's real advantage is the 4× smaller signature,
   but the signature stays on the user's phone and is never sent, so that
   does not matter here.
2. **Wide Poseidon depends on the back end.** Compressing the public key
   with t = 17 cuts constraints by 34% and the proving work after synthesis by
   about 35% (0.26 s vs 0.39 s), but arkworks' generic Poseidon gadget makes
   synthesis 4× slower, so end-to-end Groth16 proving is 2.4× slower. Not
   adopted now; revisit in the STARK port, where hash cost is paid per trace
   row, not through R1CS construction.

### Why not a standard stateless signature? (SLH-DSA estimate)

Unlinkability needs the signature verified inside the proof, and there every
WOTS chain must be computed in full (the digits are private). Counting FIPS
205 hash calls, whose formulas reproduce the standard's signature sizes for all six
parameter sets, and assuming about 27k R1CS per SHA-256 compression and about 60k per
SHA-512 compression (`slh_dsa_estimate.py`):

| Parameter set | Signature | SHA-2 compressions | R1CS (SHA-2) | × ours | Poseidon-SPHINCS+ (non-standard) | × ours |
|---|---|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 7,856 B | 3,999 | 1.1 × 10^8 | 784× | 1.27 M | 9.2× |
| SLH-DSA-SHA2-128f | 17,088 B | 12,081 | 3.3 × 10^8 | 2,367× | 3.70 M | 26.9× |
| SLH-DSA-SHA2-192s | 16,224 B | 5,753 | 1.7 × 10^8 | 1,218× | 1.82 M | 13.2× |
| SLH-DSA-SHA2-256s | 29,792 B | 8,590 | 2.5 × 10^8 | 1,809× | 2.69 M | 19.5× |

"Ours" = hidden-signature layer of the unlinkable circuit (Lamport + 30
Merkle levels = 137,796 constraints). So statelessness costs about 9 to 40×
even with a ZK-friendly hash, and about 800 to 3,700× with the standardised
SHA-2 instantiation. This is the quantitative answer to "why not simply use
SLH-DSA?". The stateful epoch design is the price of an in-proof signature.
The SHA-2 R1CS constants are assumptions; the hash counts are exact.

### Provisioning: epoch subtrees (step 2)

A monolithic 2^20-leaf device tree needed 8.0 h of key generation. It is
replaced by 2^10-leaf epoch subtrees, generated on demand and certified by the
device's ML-DSA-65 key through the registry. This avoids an XMSS^MT upper
layer, which would add a second Lamport verification (+123k constraints)
inside every proof. The one-time secrets are now derived with SHA-512
instead of Poseidon, since they never enter a circuit (`keygen_bench`):

| | Before | After |
|---|---|---|
| One-time key generation | 27.4 ms | 12.4 ms (−55%) |
| Before the first proof | 8.0 h (2^20 tree) | 12.7 s (one 2^10 epoch) |
| Registry work | – | enroll 0.13 ms once; 1.3 ms per epoch (ML-DSA verify) |
| Circuit Merkle levels | 20 + 16 = 36 | 10 + 20 = 30 |

The unlinkable circuit itself is unchanged: `n4_link` gives the same numbers.
Statefulness is managed (monotonic epoch counter, one leaf per trace), not
removed. The registry learns which device owns which epoch root, but a proof
never reveals which root it uses.

### N5 mechanism: per-trace budget with exact yes/no proofs

* **Scan circuit** (`budget.rs`): one pass over the private trace computes
  the policy outcome, so the prover can prove "holds" **or** "does not
  hold". It matches `find_witness` on 3,000 random cases, and a wrong outcome
  is never provable. Cost is about 450 constraints per fix for a 2-step
  policy (57k at n = 128, versus 1.6k for the selector circuit, which can only
  prove "holds").
* **Budget:** public nullifier N = Poseidon(k_D ‖ V ‖ j) (device budget key, since 3 Oct 2026; was C ‖ V ‖ j) with a hidden slot
  0 ≤ j < B, on top of the unlinkable relation. The verifier rejects repeated
  nullifiers. Total 215,091 constraints at n = 128 after the 16/17-bit optimisation (240,599 before; +18% over the unlinkable
  circuit), and proving takes about 1.5 s. `budget_demo` on a real GeoLife trace
  with B = 6: six answers (3 yes, 3 no) are accepted, queries 7 to 9 are
  refused, and a replayed proof is rejected.

Anonymity set (median remaining candidates) under the adaptive,
popularity-informed verifier (`n5_budget`, 30 trials; 250 m / 1 km zones):

| Scope (M) | Charge | B = 2 | B = 4 | B = 6 | B = 10 |
|---|---|---|---|---|---|
| Porto (2,000) | every answer | 1,374 / 431 | 174 / 107 | 45 / 27 | 2 / 2 |
| Porto (2,000) | "yes" only, cheap attacker | 1 / 1 | 1 / 1 | 1 / 1 | 1 / 1 |
| GeoLife users (80–670) | every answer | 22–171 | 6–54 | 2–14 | 1–5 |
| GeoLife users (80–670) | "yes" only, cheap attacker | 1–6 | 1–3 | 1–3 | 1–3 |

What this shows:

1. **Budgets only work if "no" costs a slot.** If only true policies yield
   proofs, a verifier that asks likely-"no" questions identifies the trip at
   B = 1 to 2, because refusals are free bits. The scan circuit (proving either
   outcome) is therefore necessary, not optional.
2. **With every answer charged, leakage is about one bit per answer.** To
   keep a non-trivial anonymity set against this verifier, B must be small:
   B = 4 leaves 6 to 54 of a user's own trips, and B = 6 leaves 27 to 45 of 2,000
   city trips. This is the measured
   privacy–utility trade-off for the paper; larger zones do not change it.
3. The attacker is strong (knows the candidate set and uses historical
   popularity); a verifier without the candidate set learns less.

Caveats: the proof system is still Groth16/BN254 (not post-quantum, and
needs a trusted setup); only the signature layer is PQ-plausible. The
registry root changes as devices join, so verifiers must accept a window of
recent roots (small anonymity-set effects).

## Roadmap (in priority order)

1. ~~**B2 + N4 linkability.**~~ Done (see N4 above). ~~Provisioning~~ done
   (epoch subtrees). ~~N5 mechanism~~ done (scan + nullifier budget). ~~Signature
   microbenchmark and SLH-DSA estimate~~ done (keep Lamport). Still to do: the
   formal unlinkability and budget games.
2. ~~**PQ back end (N3).**~~ End-to-end on RISC Zero done; Plonky3
   components done. Remaining: link the Plonky3 tables into one proof.
   The original plan for this step was: Port `ordered.rs` to a hash-based STARK with a
   zero-knowledge (trace-masking) mode, and compare the three signature
   instantiations (a) ML-DSA in-circuit, (b) ML-DSA over a Merkle root
   outside, (c) ML-DSA-certified epoch key plus a circuit-friendly hash-based
   signature.
3. **Commitment cost.** Merkle commitment with openings only for selected
   points.
4. **Policy language (N2).** Dwell circuit, multi-step B3, polygon zones,
   several ordered clauses per proof.
5. **Zones from real places** (OSM, or the Foursquare POIs already in
   `data/`) instead of trace-anchored boxes.
6. **B1** (independent window-and-box proofs, Li et al. 2021).
