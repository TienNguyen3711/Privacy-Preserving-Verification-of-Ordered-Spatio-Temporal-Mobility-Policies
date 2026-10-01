"""Estimate delta_Delta (Proposition 1): the probability that a proof is not
ready within the release latency Delta, under CPU load.

Each sample is one real wallet request with no release padding (latency 0),
timed from process start to output: reservation, proving in the worker
process, completion and verification. This over-approximates the time to a
ready proof. Outcomes alternate yes/no. Load levels: k busy-loop processes
(one core each) during the sample, and two concurrent provers. Levels are
interleaved round by round in rotating order, with a pause between samples,
so that heat and drift do not confound the level.

For each Delta the estimate is k/n with a one-sided 95% Clopper-Pearson upper
bound. Each sample is appended to results/delta_under_load.csv as soon as it
is measured, so the run can be split into chunks of rounds:

    python3 python/benchmarks/delta_under_load.py --start 0 --rounds 5
    python3 python/benchmarks/delta_under_load.py --summarize   # writes the JSON
"""
import argparse
import csv
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

from scipy.stats import beta

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'zkvm/target/release/wallet_prove'
DELTAS = (30, 45, 60, 90, 120)
POLICIES = {
    'yes': {'steps': [{'zone': {'xmin': 0, 'xmax': 4294967295, 'ymin': 0, 'ymax': 4294967295}, 'max_gap': None}], 'avoid': None},
    'no': {'steps': [{'zone': {'xmin': 4294967295, 'xmax': 4294967295, 'ymin': 4294967295, 'ymax': 4294967295},
                      'max_gap': None}], 'avoid': None},
}


def upper95(k, n):
    return 1.0 if k == n else float(beta.ppf(0.95, k + 1, n - k))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n', type=int, default=20, help='total rounds (one sample per level per round)')
    ap.add_argument('--start', type=int, default=0)
    ap.add_argument('--rounds', type=int, default=None)
    ap.add_argument('--summarize', action='store_true')
    a = ap.parse_args()
    if 'RISC0_DEV_MODE' in os.environ:
        raise RuntimeError('unset RISC0_DEV_MODE')
    cores = os.cpu_count()
    levels = [('idle', 0, 1), ('50% cores busy', cores // 2, 1), ('100% cores busy', cores, 1),
              ('200% cores busy', 2 * cores, 1), ('two concurrent provers', 0, 2)]
    out_csv = ROOT / 'results/delta_under_load.csv'
    fields = ['round', 'level', 'busy_processes', 'concurrent_provers', 'outcome', 'ready_s']
    if a.summarize:
        return summarize(out_csv, levels, cores)
    stop = a.n if a.rounds is None else min(a.n, a.start + a.rounds)
    with tempfile.TemporaryDirectory(prefix='delta-load-', dir=ROOT / 'work') as td:
        d = Path(td)
        for name, pol in POLICIES.items():
            (d / f'{name}.json').write_text(json.dumps(pol))
        wallets = {}
        for li, (level, busy, parallel) in enumerate(levels):
            wallets[level] = []
            for j in range(parallel):
                w = d / f'w{li}-{j}'
                subprocess.run([str(BIN), '--legacy-plaintext', '--wallet', str(w), '--init', '--traces',
                                str(ROOT / 'work/n1_geolife.jsonl'), '--n', '32', '--budget', str(a.n + 1),
                                '--latency-ms', '0', '--local-registry'], check=True, capture_output=True)
                wallets[level].append(w)
        # Interleave levels round by round (rotating order) so that heat and
        # drift over the run do not confound the load level.
        for i in range(a.start, stop):
            outcome = 'yes' if i % 2 == 0 else 'no'
            order = levels[i % len(levels):] + levels[:i % len(levels)]
            for level, busy, parallel in order:
                hogs = [subprocess.Popen(['python3', '-c', 'while True: pass']) for _ in range(busy)]
                try:
                    time.sleep(2)

                    def one(w):
                        t = time.monotonic()
                        p = subprocess.run([str(BIN), '--legacy-plaintext', '--wallet', str(w), '--policy',
                                            str(d / f'{outcome}.json'), '--request-id', f'r{i}',
                                            '--verifier', '00' * 31 + '09'], capture_output=True)
                        assert p.returncode == 0 and len(p.stdout) > 100_000, p.stderr.decode(errors='replace')
                        return time.monotonic() - t

                    with ThreadPoolExecutor(parallel) as ex:
                        times = list(ex.map(one, wallets[level]))
                finally:
                    for h in hogs:
                        h.kill()
                    for h in hogs:
                        h.wait()
                new = not out_csv.exists()
                with open(out_csv, 'a', newline='') as fh:
                    wr = csv.DictWriter(fh, fieldnames=fields)
                    if new:
                        wr.writeheader()
                    wr.writerow({'round': i, 'level': level, 'busy_processes': busy, 'concurrent_provers': parallel,
                                 'outcome': outcome, 'ready_s': times[0]})
                print(i, level, outcome, f'{times[0]:.1f}s', flush=True)
                time.sleep(3)  # cool-down between samples


def summarize(out_csv, levels, cores):
    rows = list(csv.DictReader(open(out_csv)))
    summary = {'cores': cores, 'levels': []}
    for level, busy, parallel in levels:
        ts = sorted(float(r['ready_s']) for r in rows if r['level'] == level)
        n = len(ts)
        entry = {'level': level, 'busy_processes': busy, 'concurrent_provers': parallel, 'n': n,
                 'median_s': ts[n // 2], 'min_s': ts[0], 'max_s': ts[-1], 'delta': {}}
        for D in DELTAS:
            k = sum(t > D for t in ts)
            entry['delta'][str(D)] = {'over': k, 'n': n, 'estimate': k / n, 'upper95': upper95(k, n)}
        summary['levels'].append(entry)
    (ROOT / 'results/delta_under_load.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
