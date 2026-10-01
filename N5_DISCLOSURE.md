# N5: protocol-to-guessing bound (A) and policy capacity (B)

This is the implementation contract for the chosen research direction. A is
the main conditional theorem target; B is supporting analysis. The numerical
implementation does **not** establish the cryptographic premises of A.
The manuscript has not yet been revised to claim these results.

The authoritative, fully scoped premise statement and conditional proof are
now in [A_PREMISES.md](A_PREMISES.md), including the ideal wallet transition,
observation model, source audit and executable counterexamples. That audit
identifies unresolved deployment obligations; completing the specification
does not mean the prototype satisfies its premises.

## A. Conditional real-view guessing bound

Let T be a finite trajectory secret, S fixed classical side information, and
p0 = E_s[max_t Pr(T=t | S=s)]. The budget B bounds the total number of
secret-dependent Boolean answers in one trace/verifier scope. For every
efficient adversary A, the proposed protocol theorem is:

    Pr[A(View_real, S) = T] <= min(1, 2^B p0) + epsilon_sim(lambda).

The probability is also at most one. The code's `guessing_bound(p0, B)`
returns only the ideal term; epsilon_sim is not estimated or set to zero
for the real protocol. For QPT adversaries this requires a corresponding
quantum-secure adaptive simulation argument. Quantum auxiliary information
is not covered by the classical-S formulation here.

Premises to establish before claiming the theorem for this implementation:

1. The full adaptive view (proofs, nullifiers, public registry context,
   sizes, timing and refusal events in the chosen observation model) can be
   simulated from S, public context, queries and at most B answer bits.
   Simulation must preserve the joint experiment with the secret and
   auxiliary information; ordinary single-proof ZK is not enough by itself.
2. Queries depend only on previous public observations and adversary
   randomness. New trajectory-dependent side information cannot arrive
   outside the stated leakage channel without being accounted for.
3. An honest wallet enforces the disclosure cap, charges both outcomes and
   follows a specified refusal policy. A verifier's duplicate-nullifier
   rejection alone does not prevent a curious verifier learning from extra
   messages. Persistent wallet state and reset/concurrency behaviour require
   a separate implementation/security review.
4. Trace commitment uniqueness and verifier identity prevent budget resets
   within this scope. Colluding verifiers require a bound on their TOTAL
   answers, not B for the coalition. Multiple traces likewise require an
   explicitly composed budget; there is no person-wide guarantee here.
5. Refusal is simulatable from the declared public transcript. Even a count
   cap can leak additional state if prior uses in another hidden session
   affect refusals; those sessions/state must be scoped into the model.

Proof sketch for the ideal part: condition on S and adversary randomness.
The adaptive decision tree has at most 2^B nonempty leaves. The contribution
of each leaf to optimal guessing success is at most the largest prior mass.
Sum over leaves and average over S/randomness. Transfer the guessing event
to the real view using the stipulated adaptive simulation guarantee.
This does not bound an unbounded decoder of computationally hidden proofs.

The cardinality inequality is standard quantitative information flow, not
a new information-theoretic formula. The intended construction-level work
is establishing its premises for authenticated, unlinkable policy proofs.
See Smith (2009), *On the Foundations of Quantitative Information Flow*,
https://doi.org/10.1007/978-3-642-00596-1_21, and the existing N5 literature
review. Simulatable refusal follows the auditing literature, e.g.
https://theory.stanford.edu/~nmishra/Papers/denialsLeakInformation.pdf.

## B. Optimal disclosure in a finite policy pool

`disclosure.optimal_disclosure(A, B, prior, objective)` takes a Boolean
queries-by-candidates matrix. Every answer costs one slot. Policies are
deterministic, all remain available, and the attacker may adapt or stop.
Repeated or constant queries cannot help this objective.

For the transcript-capacity objective:

    F(empty, b) = 0
    F(C, 0) = 1                          for nonempty C
    F(C, b) = max(1, max_P [F(C_P0,b-1) + F(C_P1,b-1)])

For uniform prior on M original candidates, optimal average exact-trajectory
guessing success is F(C_initial,B)/M. In particular:

    F(C,B) <= min(2^B, number of policy-equivalence classes in C).

The equivalence classes group trajectories with identical answers to every
policy in this pool. This ceiling need not be attainable at finite B.

For a nonuniform prior p, use terminal reward max_{t in C} p(t), retaining
ORIGINAL, unnormalised-within-the-node masses, and add branch rewards.
This yields optimal average posterior guessing success. Maximising the
number of leaves is generally a different objective with a skewed prior.
The runner computes both objectives separately. Its skewed prior is a
sensitivity scenario, not a historical-data estimate.

The solver returns a replayable optimal tree. `DisclosureSolver` now uses
integer bitsets over global policy-equivalence classes, removes duplicate
and complementary queries, and memoises subproblems across budgets. Each
class contributes its largest original prior weight. Input float weights
are converted to exact integer ratios for comparisons and pruning; output
probabilities remain floats (tests use tolerance).

Branch-and-bound uses the sum of the largest min(2^depth, remaining classes)
class weights as an admissible guessing ceiling, together with the same
leaf-count ceiling. It stops only when a ceiling is reached or a branch
cannot improve the lexicographic objective. This preserves exact optimality
for the represented weights; it is not approximate early stopping.

Worst-case search is still exponential. A state limit raises
`SearchLimitExceeded`; no approximate value is labelled exact. The limit
is cumulative per reusable solver instance. Returned state counts record
new states for each call. `optimal_disclosure` retains the one-call API.

The experiment runner evaluates each distinct policy only once across nested
pools, shares answer matrices and capacity results across priors, and uses
the capacity solution directly for uniform guessing. It creates separate
weighted solvers for nonuniform priors. Cached work is marked in the CSV;
near-zero reused timings must not be interpreted as fresh solver timings.
Historical experiment artifacts have not been overwritten.

Reproducible comparison with the archived original solver:

```sh
PYTHONPATH=python python3 python/benchmarks/benchmark_disclosure.py
```

This checks all completed initial-evaluation settings and benchmarks fresh
solvers on the same answer matrices, excluding matrix evaluation. The old
implementation lives only in `python/benchmarks/disclosure_reference.py`.
New outputs are under `results/n5_optimized/`.

This is a specialisation of established adaptive QIF / decision-tree
optimisation: Boreale and Pampaloni (2015),
https://lmcs.episciences.org/1606. Novelty must come from a mobility-specific
result or analysis, not from renaming the Bellman recurrence.

## Experiments and interpretation

Run from `Codebase/code`:

```sh
PYTHONPATH=python python3 -m unittest discover -s python/tests -v
PYTHONPATH=python python3 -m zkmob.n5_capacity
PYTHONPATH=python python3 -m zkmob.n5_capacity --input work/n1_porto.jsonl
```

Outputs: `results/n5_capacity_<source>.csv` and a matching JSON manifest
with candidate fixes/IDs, policies, priors, parameters, input hash and trees.
All defaults are deterministic (seed 1, 24 candidates, 4 zones, B=0..3).
These are small exact-search experiments, not replacements for the earlier
large-dataset leakage experiments. Optimality holds ONLY for the recorded
finite pool/candidate universe/prior, not every expressible mobility policy.

The nested pools retain all earlier queries:

1. Visit.
2. Visit + ordered pairs.
3. Those queries + ordered pairs with a relative upper time bound.
4. Those queries + timed ordered pairs conjoined with one avoidance zone.

Default queries fit the current circuit bridge. `--include-dwell` adds a
fifth pool explicitly labelled reference-only: no dwell circuit exists.
Policies use the original sampled fixes and `policy.evaluate`, without time
resampling; claims do not concern motion between GPS samples. Candidate
trajectories are taken from the N1 JSONL exports once per trip ID. The pool
is anchored on the known candidate universe, not learned from a held-out
history period. Sampled candidate priors include the truth by construction.
Increasing a nested pool cannot reduce optimal disclosure, but can leave it
unchanged; a zero increment is a valid result. Trace-anchored zones and
sample size limit generalisation.

`leakage.exact_partition` still measures the specified GREEDY attacker
exactly. It does not find the optimal strategy. Existing results remain
separate from the new optimum calculations.

Initial validation: 31 Python tests pass, including 10 new A/B tests.
The default run and runs on all three existing N1 exports produced 128
settings (4 sources x 4 pools x 4 budgets x 2 priors), with no ideal-bound
violations. Every exported tree was replayed against `policy.evaluate`
and its leaf reward checked against the CSV.

For the uniform prior, B=3 and 24 candidates, the stored optimum is:

| Source | Visit | + ordering | + relative time | + avoidance |
|---|---:|---:|---:|---:|
| Synthetic | 4/24 | 8/24 | 8/24 | 8/24 |
| Porto N1 sample | 5/24 | 5/24 | 6/24 | 6/24 |
| GeoLife N1 sample | 4/24 | 4/24 | 4/24 | 4/24 |
| T-Drive N1 sample | 4/24 | 4/24 | 4/24 | 4/24 |

The ideal A bound is 8/24 for each row. These are single-seed small-pool
checks, not population estimates or evidence that each added capability
strictly increases disclosure. The skewed-prior results are stored separately.

Finally, these guarantees average over transcripts. One singleton query
can identify its rare positive target with B=1 even while average guessing
success is at most 2/M. A test records this counterexample; the budget does
not establish per-transcript anonymity or pointwise leakage <= B.

## Remaining work for the paper

A larger initial evaluation is available via `python -m zkmob.n5_initial_eval`
(with `PYTHONPATH=python` from `code/`), followed by
`python -m zkmob.n5_initial_report`. It uses 64 candidates, five seeds,
six zones, budgets 0–4 and two geometry/time settings on real data.
Results, replay status, runtime measurements and plots are kept separately
in [results/n5_initial_eval/REPORT.md](results/n5_initial_eval/REPORT.md).
Plot generation additionally requires matplotlib; the solver requires numpy.

- Prove adaptive view simulation, including nullifiers and the precise
  wallet/refusal model, under the chosen quantum threat model.
- Audit/implement wallet-side persistent enforcement across resets and
  concurrent sessions; the new Python analysis is not that enforcement.
- Extend evaluation beyond small finite pools, with either tractable
  mobility-specific bounds or explicitly labelled approximation guarantees.
- Fit/validate historical priors before making empirical nonuniform-prior
  claims; measure several seeds, geometries and dataset scopes.
- Integrate a conditional theorem and correctly scoped results into
  `paper/main.tex` after reviewing these premises and evidence.
