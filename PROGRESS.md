# Paper 3 — Progress Summary (last updated 29 September 2026)

This file summarises everything done so far for Paper 3: research direction, literature verification, novelty, codebase, and next steps. Technical details of the code are in `README.md` in the same folder.

## Latest N5 implementation: A main theorem target, B supporting analysis

Full proofs, QROM and A4 (29 Sep 2026, later): `paper/main.tex` Appendices
A–E give full classical-ROM proofs of evidence soundness and presentation
unlinkability (both theorem statements corrected: soundness loses a factor K,
the number of admitted one-time keys; unlinkability gains a 4q_H/2^n term),
their QROM instantiation via O2H (Ambainis–Hamburg–Unruh 2019), an explicit
A-STARK assumption (backend ZK/knowledge soundness, cf. Chiesa–Manohar–
Spooner 2019), and a metadata observation model (Proposition). Key finding:
the 128-bit blind gives only about q_H 2^-64 against quantum queries; a
256-bit blind is needed for a 128-bit PQ target (implemented 29 Sep 2026:
zkVM blind is 32 bytes, wallet format v2, v1 wallets rejected).
A4 timing experiment (`python -m zkmob.a4_timing`, 24 RISC Zero proofs,
`results/a4_timing*.{csv,json}`): no detectable outcome dependence of proving
time (p = 0.82), identical receipt sizes and padded cycles, but guest cycle
counts separate the outcomes (~76 cycles). Fixed-latency release is
implemented in `wallet_prove` and was revised on 1 Oct 2026 after the logic
review (`reviews/2026-10-01/`, see `response.md` there): durable deadline
(wallet v3), completion committed at the deadline, overrun reported at the
deadline with the prover's stdio detached, policy domain validated before
reservation. Real-prover smoke: yes/no released at 45.05/45.06 s (Δ=45 s);
overruns reported (incl. end of output) at 1.03/1.04 s (Δ=1 s); two ledger
commits per request (`results/wallet_protection_smoke.json`). Crash between
proof and release: retry released at 60.5 s for a 60 s deadline
(`results/release_window_regression.json`). Person-level N5 (Experiment B)
now uses the exact without-replacement posterior, 200 trials
(`results/n5_bounds_users.csv`; old file kept as `.before_R6.csv`).
Follow-up (1 Oct 2026): prover runs in a killable process group (no orphaned
r0vm after expiry); global ML-DSA registry for many devices
(`python/benchmarks/global_registry_smoke.py`: 5 wallets / 4 devices,
10 presentations, one root, 0% linked pairs; local-registry control 100%
same-trip linked); simulated power loss (`host/tests/power_loss.rs`): torn
pending snapshots bricked the wallet before the fix, now all 11 crash states
recover without refund; delta_Delta under CPU load measured by
`python/benchmarks/delta_under_load.py`. The first delta run exposed a wallet
performance bug (receipts stored inline in the state: request cost grew by
~1 s per stored receipt); wallet v4 stores receipts as separate encrypted
files, and the measurement interleaves load levels to avoid drift. Result
(97 proofs): median ready time 24.9 s idle, 40.2/58.0/89.2 s at 50/100/200 %
cores busy, 50.0 s with two concurrent provers; Δ=120 s never overran
(δ ≤ 0.15 per level at 95 %), Δ=45 s always overran at ≥100 % load.

Security games and credential literature added (29 Sep 2026): `paper/main.tex`
Sec. III-C now defines evidence soundness and presentation unlinkability as
games with proof sketches (classical ROM; QROM, PQ ZK of the STARK backend and
A4 metadata remain open). New literature (`paper/lit_review_credentials.md`):
zk-creds (IEEE S&P 2023) already uses Merkle-membership commitments, predicates
over signed passports and a PRF(epoch||ctr) rate-limit token; our nullifier is
that pattern without an epoch. Distinct content: trajectory predicates (N1),
measured in-proof PQ evidence authentication, and prover-side budgets that
charge both outcomes (N5).

Encrypted snapshots and an online CAS ledger are implemented (2026-09-29).
Fifteen wallet tests pass, including stale-clone rejection and interrupted-write
recovery. See [WALLET_PROTECTION.md](WALLET_PROTECTION.md). The independent
production host is not yet deployed; ledger integrity and honest clients remain
assumptions. Earlier progress entries below describe their historical scope.

Durable wallet implemented (2026-09-29): `zkvm/host/src/wallet.rs` and
`wallet_prove` store immutable trace evidence/cap, atomic pending reservations
and verified receipts on disk (private permissions, OS process lock, fsync,
atomic rename). Requests are bound to the complete statement; retries reuse
stored receipts, both outcomes spend budget, and proving/output failures do
not refund it. Randomized local setup uses OS entropy; deterministic setup
is explicitly `setup_fixture`. See [storage specification](WALLET_STORAGE.md).
This closes local restart/concurrency gaps, not backup rollback, wallet
cloning, verifier authentication, certified registry admission or A5.
Validation: 7 disk-wallet tests, existing guest rejection test and 41 Python
tests pass. A real-prover check generated yes/no STARK receipts, restarted
between operations, recovered identical cached receipts and rejected
exhaustion/cap changes/reinitialisation; `results/wallet_storage_smoke.json`.

A premises specification completed on 2026-09-29:
[A_PREMISES.md](A_PREMISES.md) defines the secret/prior/context, complete
session scope, honest-wallet/malicious-verifier model, immutable lifetime
budget, atomic reserve-before-release, idempotent policy-bound retries,
simulatable control flow and joint adaptive simulation obligation. It gives
a conditional proof and a source-to-premise audit. Deployment obligations
remain open: the wallet is RAM-only and accepts caller-supplied caps; zkVM
benchmark setup uses deterministic secrets and synthetic registry admission.
Seven executable counterexamples record why these distinctions matter.

Solver B optimisation completed: bitsets over policy-equivalence classes,
exact integer-weight branch-and-bound, query deduplication and cache reuse
across budgets/priors. All 1,360 prior settings match, 34 tests pass, and
the formerly state-limited synthetic seed 5 now completes. Fresh-solver
benchmarks on four saved inputs (two priors, median of three repetitions)
show 24–4,415x speedups; these are instance-specific, excluding policy
evaluation and runner cache reuse. See [optimisation report](results/n5_optimized/REPORT.md).

Initial expanded evaluation: 64 candidates, six zones, five seeds, B=0–4,
uniform and hypothetical rank-skewed priors. All 30 real-data runs and four
of five synthetic runs completed and their trees were replayed (1,360 rows;
zero ideal-bound violations). Synthetic seed 5 exceeded the 200,000-state
guard and is explicitly excluded from summaries. All 31 Python tests pass.
See [initial evaluation report](results/n5_initial_eval/REPORT.md), including
seed ranges, resource limits and finite-pool interpretation. The ideal bound
can be loose and becomes trivial for the chosen skewed prior from B=3;
relative-time queries did not improve the B=4 optimum in the tested real-data
pools. These findings do not establish cryptographic simulation.

- Added `disclosure.py`: the ideal `min(1, 2^B p0)` guessing bound plus exact
  finite-policy decision-tree optimisation, with separate capacity and
  nonuniform-prior guessing objectives, replayable trees and a state guard.
- Added `n5_capacity.py`: nested visit / ordering / relative-time / avoidance
  pools using the reference semantics; optional dwell is explicitly
  reference-only. Runs on synthetic traces or existing N1 JSONL exports.
- Added independent exhaustive-tree, semantic-family and rare-outcome tests.
- The skewed prior is a sensitivity scenario; these small closed-world
  experiments are not a held-out historical-prior evaluation.
- Full premises, proof sketch and outstanding enforcement/simulation work:
  [N5_DISCLOSURE.md](N5_DISCLOSURE.md). A is a conditional theorem target,
  not a completed security proof. The manuscript still requires integration.

---

## 1. Topic

**Privacy-preserving verification of ordered spatio-temporal mobility policies over authenticated trajectories, with post-quantum-secure composition.**

A device records and signs a trajectory. The user then proves, with a zero-knowledge proof (ZKP), that the trajectory satisfies a policy, for example "visited A → B → C in order", "reached B within Δt of A", or "never entered restricted zone Z". The verifier learns only whether the policy holds, not the actual route. The whole chain (signature → commitment → proof) must remain secure against a quantum-capable adversary, using existing standardised PQC primitives rather than new ones.

**Working contribution statement:** a device signs a trajectory once; the user proves many ordered, temporally constrained policies to many verifiers, without revealing the route, without proofs being linkable to each other, and with security that holds against quantum adversaries.

---

## 2. Decisions made

| Decision | Detail |
|---|---|
| Evidence sources | Only peer-reviewed work is used as evidence. Preprints (arXiv, ePrint) are still cited as prior art for novelty, but their numbers are not relied on. |
| Role of ZKP | ZKP is the core. PQ signatures and commitments anchor the proof to real, attested data. |
| Why ZKP rather than alternatives | TEEs require trusting hardware; HE and MPC are not publicly verifiable or need interaction; DP adds noise and cannot prove a policy exactly. ZKP is non-interactive, publicly verifiable, and reveals exactly one bit. |
| Paper scope | Option A: RQ1 + RQ2 + RQ4, with RQ3 as a measured section plus a simple mechanism. The main axis is N3 + N4 (medium reviewer risk); N1 is the capability that makes the system useful. |
| Target venues | IEEE TIFS / TDSC, PoPETs. |
| No training step | There is no model to train. Security is established by proof; data is used to measure cost, correctness, and leakage. |

### Research questions

- **RQ1 (expressiveness):** how to encode policies with ordering, relative time bounds, avoidance, and dwell as a fixed circuit.
- **RQ2 (PQ composition):** how to compose a standardised PQ signature, a hash-based commitment, and a hash-based proof, and how to prove a composition theorem.
- **RQ3 (unlinkability and leakage):** what many proofs over the same trajectory reveal in aggregate.
- **RQ4 (cost):** the overhead of PQ security and ordering compared with baselines.

---

## 3. Literature verification

### 3.1 Material folder (29 files, 27 distinct papers)

- Two duplicates: *PQC for ITS – implementation-focused review* and *Post-Quantum ZKP … Decentralized CAV*.
- *Efficient Zero Knowledge for Regular Language.pdf* (35 MB) is the entire SecureComm 2023 Part I proceedings. The relevant paper is pp. 369–394 (Raymond et al., zkreg).
- The Li et al. 2021 PDF (previously recorded here as "Lin et al.") has a shifted font encoding; decoding it gives the authors Yunhui Li, Jingwen Li, Shaofu Lin, Huamin Chen and Xiaofeng Jia (DOI 10.1109/ICCSMT54525.2021.00098). Still worth checking its evaluation scope against the IEEE Xplore copy.
- The ZKLP file is the preprint; replace it with the IEEE S&P 2025 version.
- Out of scope, can be removed: *HPC–Quantum convergence*, *Cyber-physical-social system*, *ZKML survey*.

### 3.2 Key findings

1. **Li et al. (ICCSMT 2021) already covers "zone + time window".** It proves that a trip within [t₁, t₂] does or does not pass through a lat/lon box, using a zk-SNARK. Temporal constraints alone are therefore **not novel**. Novelty must come from *ordering + relative time + authenticated evidence + PQ*.
2. **Bogdanov et al. (ARES 2025 Workshops) sign with ECDSA, and the trail hash is a public input.** Proofs over the same trail are therefore linkable. This is concrete published evidence for claim N4.
3. **Ordering already exists in regex/automata form** (Reef, USENIX Security 2024; zkreg, SecureComm 2023; Zombie, NSDI 2024), but without metric time, without binding to a device signature, and without PQ security.
4. **ZK for temporal logic:** only a 2026 preprint (Berrang et al., ZK model checking). It proves LTL over a hidden system, not over a recorded trajectory, and is not PQ.
5. **Luo et al. (ePrint 2023/643, ZK-regex)** is still a preprint; its PQ status is unclear.

### 3.3 Verified venues

ZKLP → IEEE S&P 2025, pp. 3440–3459 · Bogdanov et al. → ARES 2025 Workshops, LNCS 15998 · Li et al. → ICCSMT 2021 · Wu et al. → IEEE ICC 2020 · Reef → USENIX Security 2024 · zkreg → SecureComm 2023, LNICST 567 · Zombie → NSDI 2024 · SHARP-PQ → IEEE TIFS 2025 · LatticeFold → ASIACRYPT 2025 · Farzaliyev et al. → J. Cryptology 2025 · PrivLocAuth → Electronics 2026 · HEDrone → SPACE 2020 · AliDrone → ICDCS 2018 · VPriv / PrETP / Milo → USENIX Security 2009 / 2010 / 2011 · ZQL → USENIX Security 2013.

### 3.4 Novelty & Capability Matrix

- Built as a web page: 30 works (24 peer-reviewed, 6 preprints) scored against 15 capabilities.
- Link: https://claude.ai/artifact/2JB9fMBb1b5MJB4w85SqsT (currently private; enable sharing from its Share menu before sending it to Dr Iynkaran).
- Also includes tabs for novelty claims, baseline → codebase mapping, and an IEEE-style LaTeX table for the Related Work section.
- **Conclusion:** no peer-reviewed work covers more than 4 of the 15 capabilities. Three columns are nearly empty: **C4** (relative time), **C9** (PQ signature on evidence), and **C10** (PQ composition argument).

---

## 4. Novelty claims

"Risk" here means **the likelihood that reviewers challenge the claim**, not the likelihood that the research fails.

| ID | Claim | Risk | Mitigation |
|---|---|---|---|
| N1 | Ordered policies with relative time bounds over one authenticated trajectory | High | Show that "discretise + regex" blows up as Δt becomes finer and gives wrong answers when coarse (the pilot already provides initial evidence) |
| N2 | Reusable policies over one signed commitment | Medium | A policy language compiled to one fixed circuit |
| N3 | End-to-end PQ composition of signature, commitment, and proof | Medium | Composition theorem; compare three instantiations: (a) ML-DSA verified in-circuit, (b) ML-DSA over a Merkle root checked outside the circuit, (c) ML-DSA-certified epoch key plus a circuit-friendly hash-based signature |
| N4 | Cross-proof unlinkability while keeping PQ security | Medium | Show that (b) exposes a stable identifier; provide an unlinkable instantiation |
| N5 | Leakage from repeated Boolean policy outcomes | High (scope) | Keep it as a measured section plus a query-budget mechanism, or move it to future work |

### Baselines (all based on peer-reviewed designs)

| ID | Baseline | Based on | Tests claim |
|---|---|---|---|
| B1 | Independent "time window + box" proofs | Li et al. 2021 | N1, N5 |
| B2 | Signed trail with a public hash | Bogdanov et al. 2025 | N4, N3 |
| B3 | Discretise, then run an automaton | Reef / zkreg | N1 |
| B4 | Our design with a classical back end | — | N3 (PQ overhead) |
| B5 | Unprotected repeated queries | Dinur & Nissim 2003; PrETP | N5 |

---

## 5. Codebase (this folder)

### Done

- **Rust (arkworks, Groth16/BN254):**
  - our circuit (`ordered.rs`): zones, ordering, time gaps, avoidance;
  - baseline B3 (`automaton.rs`), now with 4 symbols so overlapping zones are handled correctly;
  - Poseidon commitment (`commit.rs`): off / binding (B2) / **hiding, C = Poseidon(r ‖ T)**;
  - exact closed-form constraint counts for both designs (checked against synthesis);
  - JSON bridge (`io.rs`) and binaries `prove_json` (one real trace) and `n1_real` (batch N1);
  - **N5 mechanism:** scan circuit proving either outcome exactly + per-verifier nullifier budget (`budget.rs`, `budget_demo`);
  - **provisioning:** per-epoch 2^10 subtrees certified by the device's ML-DSA key via the registry; SHA-512 derivation of one-time secrets (`keygen_bench`);
  - **step 6:** device signatures (`sig.rs`): B2 with ECDSA P-256 or ML-DSA-65 (FIPS 204); Lamport one-time keys over Poseidon in an XMSS-style device tree; a device registry admitting keys only with a manufacturer ML-DSA-65 certificate; the **unlinkable circuit** (`unlinkable.rs`); the N4 experiment (`n4_link`);
  - the N1 pilot program.
- **Python:**
  - reference policy semantics (`policy.py`), the ground truth for every circuit;
  - loaders for GeoLife, T-Drive and Porto with cleaning, segmentation and a time-based split (`datasets.py`);
  - policy → circuit compiler and prover runner (`bridge.py`);
  - N1 real-data workload and report (`n1_export.py`, `n1_report.py`);
  - B5 leakage simulation, synthetic (`leakage.py`) and real-data (`n5_real.py`), and budget curves (`n5_budget.py`).
- **Tests (rerun 29 Sep 2026):** 41 Python, 24 Rust (arkworks), 3 zkVM-core and 20 wallet tests (13 anchor + 7 storage), all passing on the Mac (Rust 1.98, Python 3.9). Feature-gated crash tests and the guest rejection test were not part of this rerun.

### Results

**Pilot (synthetic):** reproduced on the Mac. Ours is unchanged at 6,301 policy constraints. The hiding commitment adds 243 constraints (268,982 in total), and Groth16 proving takes 2.0 s. The 4-symbol B3 is slightly more expensive than before (5 s: 903,593 constraints).

**Proof on a real trace (step 4):** a GeoLife trip (146 fixes, 10 min) proven with ordering, gap, avoidance and a hiding commitment: 85k constraints, 0.5 s to prove, verified. Porto and T-Drive also work.

**N1 on real data** (1,600 policies per dataset, 4,800 in total; Rust and Python agree on all 4,800). B3 error with the discretisation most favourable to B3, and median B3/ours constraints:

| w | GeoLife | Porto | T-Drive |
|---|---|---|---|
| 300 s | 14.2% · 0.61× | 31.4% · 1.10× | 12.4% · 11.9× |
| 60 s | 3.4% · 3.1× | 6.9% · 4.8× | 5.2% · 66× |
| 5 s | 0.6% · 77× | 0.6% · 90× | 0.5% · 2,261× |

- Where B3 is no more expensive than ours, it gets 8–55% of policies wrong. To get below 1% error it needs w ≤ 10 s, which costs 28–720× more.
- With the carry-forward discretisation that the B3 circuit actually computes, errors are much higher (T-Drive keeps an error floor of about 11% at every w).
- At fine w the remaining errors are mostly false positives, i.e. B3 proves false statements.

**N5 on real data** (time split: history 70% → query zones, last 30% → candidates):
- Porto, 2,000 trips: an adaptive verifier using historical popularity identifies the trip in 70–88% of trials within 20 queries.
- GeoLife, within one user's own trips: 32–90% within 10 queries.
- Random queries identify almost nobody.
- Larger zones do not help, which confirms the query budget as the mechanism to study.

**N4 / step 6 (signed traces and linkability)**: 4 devices × 3 real GeoLife trips × 3 policies = 36 presentations per design.

| Design | Constraints | Prove | Presentation | Linked: same trip / same device / other device |
|---|---|---|---|---|
| B2-ECDSA | 48,217 | 0.37 s | 257 B | 100% / 100% / 0% |
| B2-ML-DSA-65 | 48,217 | 0.37 s | 5,421 B | 100% / 100% / 0% |
| B2-ML-DSA-65, hiding C | 48,460 | 0.37 s | 5,421 B | 100% / 100% / 0% |
| **Unlinkable (ours)** | 182,391 | 1.32 s | **128 B** | **0% / 0% / 0%** |

- Bogdanov-style B2 is linkable with either signature scheme: C links every proof about a trip, and the device key links every trip of a device. Hiding C does not help, because C is still shown.
- Switching B2 to ML-DSA makes it PQ but 21× larger, and it is just as linkable.
- The unlinkable design shows only the policy and the registry root, and its presentation is smaller than any B2 variant. It costs 3.5× more proving.
- Lamport verification accounts for 68% of the constraints. It is the next thing to optimise (e.g. WOTS+).
- The unlinkable circuit rejects five forgeries in the tests: an unsigned trace, a wrong blinding value, an unregistered device, a false policy, and a wrong registry position.

**N5 mechanism (budget)**: the verifier accepts at most B answers per trace, with a nullifier N = H(C, V, j), 0 ≤ j < B. Anonymity set (median candidates left) under the adaptive, popularity-informed verifier:

| Scope | Charge | B = 2 | B = 4 | B = 6 | B = 10 |
|---|---|---|---|---|---|
| Porto (2,000 trips) | every answer | 431–1,374 | 107–174 | 27–45 | 2 |
| Porto | "yes" only | 1 | 1 | 1 | 1 |
| GeoLife users (80–670 trips) | every answer | 22–171 | 6–54 | 2–14 | 1–5 |

- **"No" answers must consume budget.** Otherwise refusals are free bits, and a verifier identifies the trip at B = 1–2. This is why the scan circuit, which proves yes *or* no exactly, is needed.
- **Leakage is about 1 bit per answer.** B = 4 leaves 6–54 of a user's trips, and B = 6 leaves 27–45 of 2,000 city trips. This is the privacy–utility trade-off for the paper.
- **Cost:** the budgeted circuit has 240,599 constraints at n = 128 (+32% over unlinkable) and proves in 1.4 s. On a real trace with B = 6: six answers accepted, then refusals, and a replayed proof is rejected.

**N5 formal model on real data** (`n5_bounds.py`):
- Lemma on charging rules: if every answer is charged, leakage ≤ B bits for any number of queries Q; if only "yes" is charged, leakage ≤ log2 Σ_{i≤B} C(Q,i), which grows with Q.
- Experiment A computes leakage exactly by enumerating the verifier's decision tree. Both bounds hold in all 108 settings and are tight:
  - min-entropy = B exactly when every answer is charged;
  - at B = 1, leakage reaches log2(1+Q) (4.4 to 7.9 bits) when only "yes" is charged.
- Experiment B (K traces of one person) shows the per-trace budget does not bound leakage about the person. With B = 4, eight traces identify a GeoLife user 85% of the time and a Porto taxi 52%, always within K·B.

**Provisioning (epoch subtrees)**:
- A 2^10-leaf epoch is ready in 12.7 s (was 8.0 h for a monolithic 2^20 tree).
- One-time key generation went from 27.4 to 12.4 ms per key (SHA-512 derivation of the secrets).
- The circuit is unchanged: there is no second in-circuit signature, unlike XMSS^MT.

**Hidden-signature choice (microbenchmark)**: the decision is to **keep Lamport (t = 3)** and close this branch.

| Variant | Constraints | Groth16 prove | Signature |
|---|---|---|---|
| Lamport t = 3 (current) | 123,306 | 0.90 s | 16.3 kB |
| WOTS w = 4 (untweaked) | 112,759 | 0.83 s | 4.2 kB |
| WOTS+ w = 4 (tweaked, as the standard proof needs) | 132,955 | 1.67 s | 4.2 kB |
| WOTS w = 16 | 254,130 | 1.76 s | 2.1 kB |
| Lamport t = 17 (wide Poseidon) | 80,925 | 2.19 s | 16.3 kB |

- WOTS+ with the tweaks its security proof needs is worse than Lamport, and w = 16 is 2× worse.
- Wide Poseidon has 34% fewer constraints, but arkworks' gadget makes circuit construction 4× slower. Revisit it in the STARK port.

**SLH-DSA (stateless, FIPS 205) verified inside the proof**: about 1.1 × 10^8 R1CS constraints for SLH-DSA-SHA2-128s, **784× our hidden-signature layer**. A non-standard Poseidon-based SPHINCS+ would still be 9–40× ours. This justifies the stateful epoch design. The hash counts are exact (the formulas reproduce all FIPS 205 signature sizes); the SHA-2 constraint costs are assumptions.

**Step 7: post-quantum back ends (hash-based, zero-knowledge, no trusted setup)**:

| Back end | Scope | Prove (n = 128) | Verify | Proof |
|---|---|---|---|---|
| Groth16 / BN254 (before) | full relation, **not PQ** | 1.4 s | 1.3 ms | 128 B |
| **RISC Zero zkVM** (SHA-256) | **full relation, end to end** | 23 s (45 s at n = 1024) | 9 ms | 224 kB |
| **Plonky3 AIR** (Poseidon2, hiding FRI) | scan + hash workload, **not yet linked** | ≈ 47 ms (89 ms at n = 1024) | ≈ 4 ms | ≈ 585 kB |

- The system now has an **end-to-end post-quantum ZK proof** (RISC Zero). The executor rejects every forgery in the tests.
- The hand-written Plonky3 components are about 30× faster than Groth16. The PQ price is proof size (hundreds of kB), not proving time.
- A compact witness encoding cut zkVM cycles 9× (3.46M → 386k), since reading input had taken 90% of the cycles.
- **Open:** link the Plonky3 scan and hash tables into one proof (a sponge table + LogUp cross-table lookups with `batch-stark`), estimated at several days of work.

### Not done / known gaps

1. ~~The commitment is not hiding~~ **Fixed:** C = Poseidon(r ‖ T). ~~Proofs remain linkable~~ **Fixed in step 6** by the unlinkable design (C and the signature are private).
2. **Security proofs incomplete:** a conditional disclosure theorem (A1–A6) with a proof is written in `A_PREMISES.md` and the paper. The soundness, authenticity and unlinkability games, and the joint adaptive simulation premise A5, are still open.
3. ~~No real data~~ **Done** for N1 and N5 (GeoLife, T-Drive, Porto). Zones are still trace-anchored boxes, not real places (OSM or Foursquare POIs).
4. ~~Proof system not PQ~~ **Fixed:** end-to-end PQ ZK proof on RISC Zero. The Plonky3 version has its components proven but not yet linked into one proof.
5. **B3 is plain R1CS:** more pessimistic than the real Reef, which uses lookup arguments. B3's cost for the any-fix discretisation is a lower bound (it does not include proving the aggregation).
6. **Device keys are stateful.** ~~8 h key generation~~ **Fixed** with 2^10 epoch subtrees (12.7 s each). The state (one leaf per trace, monotonic epochs) is still the device's responsibility.
7. **No formal unlinkability or budget game yet.** The experiment shows only that proofs share no values, which is the equality attack.
8. **Budget assumptions:** V must be an authenticated verifier identity (otherwise Sybil verifiers each get B answers); the device must commit each trace exactly once; the budget is per verifier, so colluding verifiers pool their B answers.
9. **Lamport cost** is still 68% of the unlinkable circuit. The benchmark shows no better one-time signature under Groth16; wide Poseidon is deferred to the STARK back end.

---

## 6. Next steps

| # | Task | Who | Status |
|---|---|---|---|
| 1 | Add blinding: C = Poseidon(r ‖ T) | code | **Done** (tests: commitments differ, proofs verify, wrong r rejected) |
| 2 | Run tests and the pilot on the Mac | Tien | **Done** (identical constraint counts) |
| 3 | Download GeoLife / T-Drive / Porto | Tien | **Done** (`data/`) |
| 4 | Python → JSON → Rust bridge | code | **Done** (zones trace-anchored; OSM/POI zones still to do) |
| 5 | Re-run N1 and N5 on real data; time-based split for N5 | code | **Done** (`results/n1_real_*`, `results/n5_real.csv`) |
| 6 | B2 + N4: sign with ECDSA and ML-DSA; compare linkable and unlinkable versions | code | **Done** (`results/n4_linkability*.csv`) |
| 7 | PQ back end (N3): STARK with a zero-knowledge mode | code | **Done** on RISC Zero (end to end); Plonky3 components done, linking open |

**In parallel, on the paper side:**
- Write the *System Model & Security Definitions* section: relation R (now concrete in `unlinkable.rs`), threat model, game-based definitions of soundness / ZK / unlinkability, and theorem statements with proof sketches.
- Draft the N1 evaluation paragraph from `results/n1_real_summary.csv`, and the N5 section from `results/n5_real.csv`.
- Resolve the remaining "?" cells in the matrix, for example the evaluation scope of Li et al. 2021 (check against IEEE Xplore).
- Search for further peer-reviewed prior work on ZK for temporal logic / timed automata.
- Check Luo et al. (ZK-regex): whether it has been published, and whether it is PQ-plausible.

**Immediate next action:** Plonky3 linking is decided against for now (RISC Zero is the end-to-end result; Plonky3 is a component study). On the paper side: integrate the `n5_bounds` results, align the N5 metric with the average-case theorem, decide the role of the wallet, and write the remaining security games.

Protected-wallet validation expanded: opt-in process-abort injection passes
eight commit-boundary scenarios (reserve and complete at four boundaries).
The wallet suites pass 17 test entries including two subprocess helpers.
Protected real STARK smoke passes for yes (26.40 s) and no (27.25 s),
byte-identical restart retries, and explicit empty stdout on expected errors.
See `results/wallet_protection_smoke.json`. No power-loss durability claim.

Additional ledger integration validation: the default wallet suites pass
18 test entries (11 anchor + 7 storage, including a subprocess helper).
New cases cover hard ledger restart, twelve concurrent wallet clones, and
lost successful commit replies followed by ledger restart for both reserve
and complete. They use the real local SQLite service and opaque responses;
no new STARK performance run or remote deployment is implied. Earlier eight
feature-gated SIGABRT scenarios were not rerun in this default-feature run.

Model/storage/metadata validation completed: default suites pass 20 entries
(13 anchor + 7 storage, including a helper). Four seeds exercise 480 reference-
model operations across three verifier scopes with wallet/ledger restarts.
Staging-path I/O errors and three snapshot truncations fail closed. ENOSPC and
fsync error injection are not covered. Real protected yes/no smoke passes
(28.94/27.57 s). `results/wallet_metadata_observations.json` records stable
ledger identity, event counts 1 -> 3 -> 5 and unchanged counts on cached retries.
Local ciphertext sizes grow 64,504 -> 835,864 -> 1,607,008 bytes. Those sizes
are storage-observer metadata, not ledger payload sizes. This is evidence of
observable metadata, not a zero-leakage result or an outcome-timing classifier.

## Stage 4 revision (3 October 2026)

- Pipeline review (reviews/2026-10-03): Stage 2.5 integrity PASS; Stage 3 five-seat
  review, Major Revision; author decisions in `stage4_author_adjudication.md`.
- N1 fair rerun: scan at 16-bit coordinates / 17-bit time (243n - 22); B3 charged
  a bucket-binding lower bound (~230 per fix) and a sound variant added
  (`n1_fair.py`, `n1_fair_summary.csv`, `n1_fair_by_factor.csv`). B3 is never more
  than 5% cheaper and then wrong on 6-55%; below 1% error 1.18-3.95x end to end.
- Device-level budget in zkVM and Groth16 (budget key, tagged registry leaf,
  device nullifier, wallet v5). New Groth16 counts: B2 47,965 / 48,208; unlinkable
  (selector) 182,139; budgeted (scan + device nullifier) 215,091 at n = 128.
- zkVM: n <= 128 at 2^19 cycles (23 s), n >= 256 at 2^20 (~52 s).
- Paper: A5 proved (Lemma 3), Theorem 1 per device with m verifiers, supplement
  `paper/supplement.tex`, response `reviews/2026-10-03/stage4_response_to_reviewers.md`.
