"""Summarise the completed n5_initial_eval sweep; make a static research plot."""
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/n5_initial_eval"
FAMILIES = ["visit", "visit_ordered", "visit_ordered_timed", "visit_ordered_timed_avoid"]
LABELS = ["Visit", "+ ordering", "+ relative time", "+ avoidance"]


def main():
    with (OUT / "all_results.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    status = json.loads((OUT / "run_status.json").read_text())
    lookup = {(r['source'], r['scenario'], r['prior'], r['family'], int(r['budget']), int(r['seed'])): r for r in rows}
    def group(source, scenario, prior, family, budget):
        return [r for r in rows if (r['source'], r['scenario'], r['prior'], r['family'], int(r['budget'])) ==
                (source, scenario, prior, family, budget)]
    lines = ["# Initial evaluation of N5 A/B", "",
             "## Design and validation", "",
             "64 candidate trajectories per run; seeds 1–5; budgets 0–4; six zones. "
             "Nested pools contain 6, 36, 66 and 186 queries. Original sampled fixes are evaluated without resampling. "
             "The primary setting uses zone half-side 150 m and relative gap 120 s; the real-data sensitivity setting "
             "uses half-side 500 m and gap 900 s. Both parameters change together, so this is not a factorial ablation.", "",
             "The pools are anchored on the known candidate universe. These are closed-world, finite-pool optima, "
             "not held-out population estimates. The rank-skewed prior is hypothetical (weights proportional to 1/rank "
             "over sorted candidate IDs), not learned from history. Dwell is excluded because it lacks a circuit.", "",
             f"Completed/replayed runs: {sum(r['status']=='completed_and_replayed' for r in status)}/{len(status)}. "
             f"Recorded settings: {len(rows)}. Bound violations: {sum(r['within_bound'] != 'True' for r in rows)}. "
             "Tree replay checks the semantic answers, branch membership, path budget and terminal guessing reward. "
             "Checks also cover nested-pool and budget monotonicity and policy-equivalence ceilings.", "",
             "## B=4, uniform prior", "",
             "Values are mean optimal guessing success across completed seeds; brackets show min–max, not confidence intervals. "
             "Prior guessing success is 1/64 = 1.5625%; the ideal A bound is 16/64 = 25%.", "",
             "| Source / setting | Completed seeds | Visit | + ordering | + relative time | + avoidance |",
             "|---|---:|---:|---:|---:|---:|"]
    for source in ("synthetic", "porto", "geolife", "tdrive"):
        for scenario in ("primary", "wide_long"):
            values = []
            for family in FAMILIES:
                g = group(source, scenario, 'uniform', family, 4)
                if not g:
                    break
                p = np.array([float(r['optimal_guess']) for r in g]) * 100
                values.append(f"{p.mean():.2f}% [{p.min():.2f}–{p.max():.2f}]")
            if len(values) == 4:
                lines.append(f"| {source} / {scenario} | {len(g)}/5 | " + " | ".join(values) + " |")
    lines += ["", "## Paired capability increments at B=4", "",
              "Each comparison retains exactly the same candidates, prior and geometry. The larger family also contains "
              "more queries, so this measures the benefit of access to the expanded finite pool, not a query-count-matched ablation.", "",
              "| Setting / prior | Ordering: improved runs | Timing: improved runs | Avoidance: improved runs |",
              "|---|---:|---:|---:|"]
    for scenario in ("primary", "wide_long"):
        for prior in ('uniform', 'rank_skewed_sensitivity'):
            vals = []
            for prev, curr in zip(FAMILIES, FAMILIES[1:]):
                pairs = []
                for r in rows:
                    if r['source'] == 'synthetic' or r['scenario'] != scenario or r['prior'] != prior or r['family'] != curr or int(r['budget']) != 4:
                        continue
                    old = lookup[r['source'], scenario, prior, prev, 4, int(r['seed'])]
                    pairs.append(float(r['optimal_guess']) - float(old['optimal_guess']))
                vals.append(f"{sum(v > 1e-12 for v in pairs)}/{len(pairs)}")
            lines.append(f"| {scenario} / {prior} | " + " | ".join(vals) + " |")
    full = [r for r in rows if r['source'] != 'synthetic' and r['family'] == FAMILIES[-1] and int(r['budget']) == 4 and r['prior'] == 'uniform']
    ratios = np.array([float(r['optimal_guess'])/float(r['ideal_guess_bound']) for r in full])
    times = np.array([float(r['guessing_s']) for r in rows])
    lines += ["", "## Bound tightness and computation", "",
              f"Real-data full-pool B=4 uniform success reaches {100*ratios.min():.1f}–{100*ratios.max():.1f}% "
              f"of the ideal bound (mean {100*ratios.mean():.1f}%). A loose bound is valid but not predictive of achievable "
              "disclosure in this restricted policy pool.", "",
              "With 64 candidates, the chosen skewed prior has p0 approximately 21.08%. The A bound saturates at 1 "
              "from B=3, so it gives no nontrivial upper bound there; finite-pool optimisation can remain informative.", "",
              f"Guessing solver time per setting: median {np.median(times):.6f} s, maximum {times.max():.4f} s. "
              f"Maximum explored guessing states: {max(int(r['search_states']) for r in rows)}. "
              f"Sum of run wall times (includes replay): {sum(r['wall_s'] for r in status):.2f} s. "
              "These Python optimisation timings are not cryptographic proving times; runs use a 200,000-state guard and a 120 s process timeout.", "",
              "## Interpretation and limits", "",
              "A is numerically consistent with all tested ideal transcripts; these experiments do not prove adaptive "
              "cryptographic simulation, PQ security or wallet enforcement. B quantifies restricted-pool disclosure and "
              "does not imply every added capability strictly increases it. Sparse/constant policy answers, equivalence "
              "classes and the query budget can all limit gains. Five seeds and 64 candidates are preliminary evidence.", "",
              "Next: inspect separating policies and constant-query rates, expand geometries and budgets, compare matched "
              "query counts, and evaluate historical priors. The real-view theorem premises remain a separate task.", "",
              "Reproduce from `Codebase/code`:", "",
              "```sh", "PYTHONPATH=python python3 -m zkmob.n5_initial_eval",
              "PYTHONPATH=python python3 -m zkmob.n5_initial_report", "```", "",
              "Artifacts: `all_results.csv`, `summary.csv`, `run_status.json`, per-run CSV/JSON/log files, "
              "and `primary_curves.png` / `primary_curves.pdf`."]
    failures = [r for r in status if r['status'] != 'completed_and_replayed']
    if failures:
        lines += ["", "## Incomplete runs", "",
                  "Failed runs are excluded from means, not replaced by approximate optima. "
                  "The synthetic summary is therefore completion-conditioned and may underrepresent harder instances."]
        for r in failures:
            log = OUT / f"{r['source']}_{r['scenario']}_seed{r['seed']}.log"
            reason = r.get('error', 'failed')
            if log.exists() and 'SearchLimitExceeded' in log.read_text():
                reason = 'exact search exceeded the 200,000-state guard'
            lines.append(f"- {r['source']} / {r['scenario']} / seed {r['seed']}: {reason}; see its log.")
    (OUT / "REPORT.md").write_text("\n".join(lines) + "\n")
    plt.rcParams.update({'font.size': 10})
    fig, axes = plt.subplots(2, 3, figsize=(12, 7), sharex=True, sharey='row')
    for i, prior in enumerate(('uniform', 'rank_skewed_sensitivity')):
        for j, source in enumerate(('porto', 'geolife', 'tdrive')):
            ax = axes[i, j]
            for family, label in zip(FAMILIES, LABELS):
                pts = [np.array([float(r['optimal_guess']) for r in group(source, 'primary', prior, family, b)]) * 100 for b in range(5)]
                mean = [v.mean() for v in pts]
                line, = ax.plot(range(5), mean, marker='o', markersize=4, label=label)
                ax.fill_between(range(5), [v.min() for v in pts], [v.max() for v in pts], color=line.get_color(), alpha=.08)
            bound = [100*float(group(source, 'primary', prior, FAMILIES[0], b)[0]['ideal_guess_bound']) for b in range(5)]
            ax.plot(range(5), bound, 'k--', label='A: ideal bound')
            ax.set_title(f"{source.title()} — {'uniform' if i == 0 else 'rank-skewed'}")
            ax.set_xticks(range(5))
            ax.grid(alpha=.2)
            if j == 0:
                ax.set_ylabel('Optimal guessing success (%)')
            if i == 1:
                ax.set_xlabel('Answer budget B')
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='lower center', ncol=5, frameon=False)
    fig.suptitle('Initial finite-pool evaluation: 64 candidates, 5 seeds\nMean curves; shading = seed range; primary geometry/time setting')
    fig.tight_layout(rect=(0, .06, 1, .92))
    fig.savefig(OUT / 'primary_curves.png', dpi=180)
    fig.savefig(OUT / 'primary_curves.pdf')
    plt.close(fig)
    print(OUT / 'REPORT.md')


if __name__ == '__main__':
    main()
