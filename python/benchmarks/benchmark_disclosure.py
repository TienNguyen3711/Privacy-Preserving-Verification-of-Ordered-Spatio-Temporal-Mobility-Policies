"""Compare the archived tuple solver with the bitset solver on identical inputs.

Run from code/: PYTHONPATH=python python3 python/benchmarks/benchmark_disclosure.py
Archived initial results are read only. Timings exclude policy evaluation and
use fresh solvers (three repetitions); runner cache reuse is not credited.
"""
import csv
import json
from pathlib import Path
import statistics
import time

import numpy as np

import disclosure_reference as old
from zkmob.disclosure import optimal_disclosure
from zkmob.policy import evaluate, policy_from_dict
from zkmob.trajectory import Point

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'results/n5_optimized'


def matrices(data):
    traces = [[Point(*p) for p in t['points']] for t in data['candidates']]
    cache, result = {}, {}
    for family, specs in data['policy_pools'].items():
        rows = []
        for spec in specs:
            key = json.dumps(spec, sort_keys=True)
            if key not in cache:
                pol = policy_from_dict(spec)
                cache[key] = [evaluate(pol, t) for t in traces]
            rows.append(cache[key])
        result[family] = np.array(rows, dtype=bool)
    return result


def replay(result, matrix, p, budget):
    leaves = set()
    for truth in range(matrix.shape[1]):
        node, depth = result.tree, 0
        while node.query is not None:
            node = node.yes if matrix[node.query, truth] else node.no
            depth += 1
        assert depth <= budget and truth in node.candidates
        leaves.add(node.candidates)
    assert len(leaves) == result.leaves
    score = sum(max(p[list(ids)]) for ids in leaves)
    assert abs(score - result.posterior_guess) < 1e-12


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    status = json.loads((ROOT/'results/n5_initial_eval/run_status.json').read_text())
    inputs = {}
    checked = 0
    for run in status:
        if run['status'] != 'completed_and_replayed':
            continue
        name = f"{run['source']}_{run['scenario']}_seed{run['seed']}"
        path = ROOT / f'results/n5_initial_eval/{name}.json'
        data = json.loads(path.read_text())
        mats = matrices(data)
        priors = {r['prior']: np.array(r['weights']) for r in data['runs']}
        with path.with_suffix('.csv').open() as fh:
            for row in csv.DictReader(fh):
                A, p, b = mats[row['family']], priors[row['prior']], int(row['budget'])
                new = optimal_disclosure(A, b, p)
                cap = optimal_disclosure(A, b, objective='leaves')
                assert abs(new.posterior_guess - float(row['optimal_guess'])) < 1e-12
                assert cap.leaves == int(row['capacity_leaves'])
                replay(new, A, p, b)
                replay(cap, A, np.ones(len(p))/len(p), b)
                checked += 1
        if name in ['synthetic_primary_seed3', 'porto_wide_long_seed3', 'geolife_wide_long_seed2', 'tdrive_primary_seed1']:
            inputs[name] = (mats['visit_ordered_timed_avoid'], priors)
        print(name, 'regression matched', flush=True)

    timings = []
    for name, (A, priors) in inputs.items():
        for pname, p in priors.items():
            times = {'old': [], 'new': []}
            for _ in range(3):
                for label, solver in [('old', old.optimal_disclosure), ('new', optimal_disclosure)]:
                    start = time.perf_counter()
                    result = solver(A, 4, p)
                    times[label].append(time.perf_counter() - start)
                    if label == 'old':
                        ref = result
                    else:
                        assert abs(result.posterior_guess-ref.posterior_guess) < 1e-12
                        replay(result, A, p, 4)
            t_old, t_new = map(statistics.median, (times['old'], times['new']))
            timings.append(dict(input=name, prior=pname, budget=4, old_s=t_old, new_s=t_new,
                                speedup=t_old/t_new, old_states=ref.states, new_states=result.states))
            print(name, pname, f'{t_old/t_new:.1f}x', flush=True)
    with (OUT/'solver_benchmark.csv').open('w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(timings[0]))
        w.writeheader(); w.writerows(timings)
    (OUT/'regression.json').write_text(json.dumps({'matched_settings':checked, 'tree_replay': True,
        'probability_tolerance':1e-12, 'benchmark_repetitions':3, 'timing_scope':'fresh solver, no matrix evaluation'}, indent=2)+'\n')
    print('verified settings', checked)


if __name__ == '__main__':
    main()
