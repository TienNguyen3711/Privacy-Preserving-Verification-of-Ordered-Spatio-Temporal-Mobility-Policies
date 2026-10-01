# A: precise premises and conditional disclosure theorem

Status: specification and conditional proof, audited against source on
2026-09-29. This completes the premise statement, **not** a proof that the
current prototype meets every premise. A disk-backed local implementation
now exists; see [WALLET_STORAGE.md](WALLET_STORAGE.md). B experiments establish neither the
simulation premise nor operational budget enforcement.

## 1. Experiment and scope

An efficiently sampleable experiment generates a finite classical secret T,
classical side information S and public setup/context K. Write Z=(S,K) and
p0=E_z[max_t Pr(T=t | Z=z)]. Fix a single recorded trace and an authenticated
verifier identity V, with cap B fixed before interaction. Include all sessions
and retries for this pair in the experiment, beginning at enrolment with zero
spent slots. Alternatively, include previous observations in Z, condition the
prior on them, and give the remaining budget a fixed public value.

The adversary may know that all challenges concern this same target. A
bounds semantic disclosure even with that knowledge; it does not establish
cross-target unlinkability. T's candidate universe and the prior must be
specified independently of the observed answers. Do not absorb a newly
revealed commitment, signature or device identifier into Z after the fact
to make the theorem vacuously true.

The wallet/device is honest for confidentiality, its state and secrets are
uncorrupted, and a single authoritative wallet controls every release for
this trace. Soundness against a malicious prover is a separate game. No
protocol can stop a cooperating owner sending its own plaintext to a
verifier. The verifier is malicious/adaptive, can ignore verification or
nullifier-rejection rules, and can replay, reorder or overlap requests.
The experiment serialises admissions through the wallet's state transition.

The QPT variant allows quantum internal computation and hash access under
the selected cryptographic model, but only classical policy queries and
classical replies. No coherent access to the trajectory oracle or initially
T-correlated quantum auxiliary register is covered. Initial adversary state
can depend on Z, but has no additional dependence on T conditional on Z.

## 2. Ideal disclosure functionality and wallet transition

The ideal functionality has hidden T, an immutable B, spent counter u, and
a map from request IDs to their canonical policy/context and response.
The scope key is private wallet state, not a new identifier published to V.

1. Authenticate V and validate the policy/context from public syntax. Check
   the pinned B, canonical encoding, permitted policy shape and registry
   context. Invalid admission returns a public, T-independent status.
2. A repeated request with identical canonical policy/context reuses its
   existing response. Reusing the ID for a different policy/context is
   rejected independently of T. Retries never allocate another outcome under
   the same slot. Recomputing a different policy with the old nullifier is
   forbidden even if the verifier would reject it.
3. For a new admissible request, if u=B return EXHAUSTED. Otherwise durably
   and atomically reserve j=u, increment u, and bind j to the request BEFORE
   evaluating or exposing any secret-dependent output. Both outcomes spend
   the reservation; neither an invalid proof nor a verifier's rejection
   refunds it. Parallel requests are linearised by this transaction.
4. Compute b=P(T), prove exactly b, and persist the bound response before
   release. A retry returns the same completed response. A pending request
   after restart may finish only that same policy/slot or remain burned;
   it must not make the slot available to another policy. Release at most
   B distinct secret-dependent answers across the scope.
5. The normal model answers every admitted request while budget remains;
   selective voluntary refusals after evaluating b are excluded. For fault
   extensions, fault/recovery schedules must be independent of T conditional
   on the permitted transcript, or their leakage must be charged separately.

The reference ideal machine uses no real-time clock. For a network theorem,
response timing, lengths, failure modes, traffic/session identifiers and
public registry changes require simulation or explicit additional leakage.
They are NOT automatically protected by the binary-output argument.
Data-dependent proving duration cannot be dismissed just because b is ZK.

Persistence requires one authoritative database and no rollback/clone of it;
ordinary file persistence alone does not prevent restoring an older backup.
Migration/recovery cannot issue a fresh budget. B is a trusted wallet policy,
not a caller-selected parameter that can be increased after exhaustion.
Authenticated V is obtained from a trusted identity binding, not a free text
verifier label. Registry epochs/key rotations do not reset this trace budget.

## 3. Premises with explicit proof obligations

**A1 — Defined prior and observation scope.** The above experiment fixes Z,
B, public shape/padding parameters and session scope. Any trace-length or
registration metadata visible before interaction belongs in Z and the
reported prior must condition on it. New information from outside the query
interface is excluded or included in a revised guarantee.

**A2 — Complete outcome semantics.** Admitted policies are deterministic
total functions on the well-formed authenticated trace domain. Both b=0 and
b=1 have the same admission/charging rule. Trace well-formedness is checked
before the interaction; malformed input must not create a secret-dependent
error oracle. Here policies concern sampled fixes, not continuous motion.

**A3 — Release enforcement.** The wallet implements the transition above,
with frozen cap, canonical identity/trace binding, atomic persistent state,
request-to-policy binding, no refunds, and no alternate disclosure path.
The guarantee counts information RELEASED, not proofs ACCEPTED.

**A4 — Public/simulatable control flow.** All rejection/retry/exhaustion
events, faults and transport metadata in the declared observation model can
be generated from Z, the requests, permitted answers and independent coins.
No unobserved prior session can change visible budget behaviour outside the
model. Secret-dependent failure would add another answer alphabet.

**A5 — Joint adaptive simulation (cryptographic obligation).** For every
efficient verifier, there exists an online simulator given Z and access only
to the ideal interface above such that the real and ideal joint experiments
are indistinguishable with advantage epsilon_sim(lambda). The comparison
must preserve correlation with the sampled T and auxiliary information, so
the efficient event "verifier output equals T" is an admissible test in the
security experiment. The simulator must respond adaptively and consistently
across all sessions in scope; ordinary single-proof ZK is insufficient.

Its output covers the public policy/outcome, proof, R,V,B,N, lengths and
all declared metadata. Replayed responses/nullifiers must be consistent;
new slots must look unlinkable except for permitted context. Nullifier
pseudorandomness is an explicit sub-obligation: hiding of C alone does not
prove that H(C,V,j) is a PRF. A hybrid proof must justify the actual tagged
hash construction, secret entropy, correlated inputs, hash-query model and
simulation of proofs about replaced statements. A fixed salt length or
fixed backend does not by itself define an asymptotic security family.

**A6 — Security parameters and trust boundary.** For the QPT claim, all
hybrids in A5 must hold against QPT distinguishers for the chosen hash,
commitment, signature/registration and proof instantiation. Specify the
security parameter, fresh secret randomness and key state. Registry
admission authenticity and trusted device recording must be established for
the authenticated-evidence claim; they are not consequences of counting
answer bits. Device/registry corruption is out of scope unless separately
modelled. No unsupported numerical PQ security level is assigned here.

## 4. Conditional theorem and proof

Under A1–A6, for each efficient adversary A (QPT in the qualified variant),

    Pr[A(View_real,Z)=T] <= min(1, 2^B p0 + epsilon_sim(lambda)).

Ideal proof: fix z and the private coins of the ideal interaction, which are
independent of T conditional on z. Policies and all non-answer messages are
functions of the preceding history. Padding stopped paths gives a binary
decision tree of depth at most B, hence at most 2^B nonempty leaves. Each
leaf contributes at most max_t Pr(T=t|z) to average exact guessing success.
Sum over leaves, then average over z and coins. Randomised classical-message
strategies satisfy the same bound; quantum internal computation gives no
extra T-dependent interface in the stated ideal model. The simulator's
independent state/messages do not introduce additional secret observations.
For initially correlated quantum side information this classical-prior
argument is not the claimed theorem.

Transfer: apply A5 to the efficient guessing-success event in the jointly
sampled experiment. The real probability differs from the ideal probability
by at most epsilon_sim. Clip the resulting upper bound at one. This proves
the conditional result without assuming that computational ZK protects
against an unbounded decoder of real cryptographic transcripts.

This is an average-over-transcripts guarantee, not a lower bound on every
posterior anonymity set. One rare singleton answer can identify its target.
For a coalition of k identities on this trace, use the TOTAL admitted budget
sum_v B_v and include their pooled context. For multiple traces and a person
secret U, specify a joint prior, use p0 for U and account for all answers;
there is no automatic person-wide guarantee from per-trace caps.

## 5. Relation to B and attribution

For fixed z, finite candidate set C and fixed policy pool P, B's optimum
is the exact ideal guessing value for that restricted experiment. With a
uniform prior it is F_P(C,B)/|C|. A refined ideal upper bound is
min(1, F_P(C,B)*max_t p(t|z), sum_E max_{t in E} p(t|z)), where E runs over
policy-equivalence classes. Average conditional values over z before adding
epsilon_sim. The empirical candidate set is not a bound for an unknown
population or arbitrary side information.

The cardinality/QIF ingredient is established mathematics, not claimed new:
[Smith 2009](https://link.springer.com/chapter/10.1007/978-3-642-00596-1_21).
Adaptive optimisation follows
[Boreale and Pampaloni 2015](https://lmcs.episciences.org/1606).
Simulatable refusals follow
[Kenthapadi, Mishra and Nissim 2013](https://theory.stanford.edu/~nmishra/Papers/denialsLeakInformation.pdf).
The proposed contribution is a correct protocol instantiation/composition
and mobility-specific analysis, not these generic inequalities.

## 6. Audit of the current source: no premise silently assumed satisfied

| Obligation | Evidence | Current status |
|---|---|---|
| A2: either-outcome relation | `rust/.../src/budget.rs::enforce_scan_policy`; `zkvm/core/src/lib.rs::check` | Implemented and tested at relation level |
| A3: slot range | Both relations check slot < B | Implemented; this alone does not enforce lifetime release count |
| A3: durable, frozen budget | New `zkvm/host/src/wallet.rs`: fsync/atomic snapshots, file lock, immutable cap; old Groth16 SlotWallet remains RAM-only | Implemented with encrypted snapshots and online CAS anchor; independent ledger integrity remains a premise |
| A3: retry-to-policy binding | New `wallet_prove` binds request IDs to complete Statements and persists verified receipts before output | Implemented for the new local proving path |
| A3: verifier rejection | `NullifierLog` records already accepted N | Useful anti-replay, not confidentiality enforcement against the verifier |
| A3/A4: concurrency, faults, timing | Disk wallet serialises processes and retains pending reservations; storage failures poison the handle; durable release deadline (v3); complete/expire committed at the deadline; prover stdio detached | Restart/concurrency/crash tested; crash-before-release regression (retry at 60.5 s for a 60 s deadline); paper Proposition now defines the observer view (statuses, lengths, release/EOF times, ledger id/type/time/revision/digest) and needs T-independent delays and fault schedules plus a per-slot expiry bound δ_Δ: measured under CPU load (Δ=120 s: 0/97 overruns, ≤0.15 per level at 95 %; Δ=45 s overruns at ≥100 % load). Prover group killed at expiry; receipts stored as separate files (v4). Residual: trusted local clock, ledger round trip in release time |
| A5: nullifier secrecy | Tagged hashes of hidden C,V,j | Hybrid proof in the classical ROM and QROM bound via O2H written (paper App. C–D); 256-bit zkVM blind implemented; backend ZK is assumption A-STARK |
| A5/A6: benchmark randomness | Renamed `setup_fixture`; new `setup_randomized_local` uses OS entropy, persisted once by disk wallet | Fresh entropy path implemented; fixture remains explicitly non-confidential |
| A6: epoch registration in zkVM demo | Both setup paths construct a local epoch/registry; randomized setup does not run ML-DSA admission | Complete admission chain still required for authenticated deployment |
| A6: blinding/security level | zkVM blind is 32 bytes (wallet v2; v1 rejected); Groth16 baseline keeps u128 (classical only) | QROM hybrid gives O(q_H 2^-128) for the blind term with a 256-bit blind (paper App. D); constants and whole-composition level not asserted |
| A5/A6: proof backend | Groth16 is classical; RISC Zero executes the relation with a succinct STARK | No complete adaptive QPT simulation proof established in this project |

In particular, a verifier with candidate traces can recompute the benchmark
zkVM fixture blind (length-derived), candidate commitments and N for each small
slot j. Matching a public N can reveal a candidate even if all policy
outcomes agree. `tests/test_a_premises.py` records this fixture-specific
counterexample. It is not an attack on a properly randomised instantiation
and does not invalidate proof correctness/performance measurements.

## 7. Acceptance criteria before promoting A to a system theorem

1. Local wallet transition is implemented in `wallet_prove` with tests for
   frozen caps, replay binding, concurrency and restart. Establish external
   rollback/clone protection before broadening the deployment claim.
2. Fresh OS entropy and trace-lifetime persistence are implemented separately
   from named deterministic fixtures. Integrate certified registry admission
   and the deployment device key lifecycle; local setup is not that chain.
3. Specify the operational observation model and implement/scope timing,
   size and failure behaviour accordingly.
4. Supply the joint adaptive simulation hybrids and backend-specific QPT
   assumptions/parameters, including nullifier generation and registration.
5. Only then present A as a security theorem for that instantiated system.
   Until then the theorem above is conditional and the audit gaps remain open.

## Online anchor implementation (2026-09-29)

[WALLET_PROTECTION.md](WALLET_PROTECTION.md) documents encrypted durable storage
and a reference independent CAS service. Client rollback and divergent clones
are rejected against the trusted current ledger. This partially instantiates A3;
it does not protect a rolled-back ledger, malicious owner or re-enrolment under
a new master key. The anchor sees stable identity and timing: exclude it from
the verifier coalition or include these observations in A4/A5. HTTPS here is
not an established PQ transport composition.
