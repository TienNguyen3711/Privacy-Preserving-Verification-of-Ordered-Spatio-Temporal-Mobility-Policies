"""Real STARK receipts through the durable wallet, each call a new process.

From code/: python3 python/benchmarks/wallet_smoke.py
Requires the release wallet_prove binary; never enables RISC0_DEV_MODE.
Private state is kept under work/; only test outcomes/timings go to results/.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    if 'RISC0_DEV_MODE' in os.environ:
        raise RuntimeError('unset RISC0_DEV_MODE')
    private = Path(tempfile.mkdtemp(prefix='wallet-smoke-', dir=ROOT/'work'))
    wallet = private/'wallet'
    binary = ROOT/'zkvm/target/release/wallet_prove'
    yes = {'steps': [{'zone': {'xmin': 0, 'xmax': 4294967295, 'ymin': 0, 'ymax': 4294967295}, 'max_gap': None}], 'avoid': None}
    no = {'steps': [{'zone': {'xmin': 4294967295, 'xmax': 4294967295, 'ymin': 4294967295, 'ymax': 4294967295}, 'max_gap': None}], 'avoid': None}
    for name, policy in [('yes', yes), ('no', no)]:
        (private/f'{name}.json').write_text(json.dumps(policy))
    rows = []

    def run(label, args, success=True):
        start = time.perf_counter()
        p = subprocess.run([str(binary), '--legacy-plaintext', '--wallet', str(wallet), *args], capture_output=True, timeout=180)
        assert (p.returncode == 0) == success, p.stderr.decode(errors='replace')
        rows.append({'case': label, 'exit_code': p.returncode, 'wall_s': time.perf_counter()-start})
        print(label, f"{rows[-1]['wall_s']:.2f}s", flush=True)
        return p.stdout

    run('initialize_randomized_disk_wallet', ['--init', '--traces', str(ROOT/'work/n1_geolife.jsonl'), '--n', '32', '--budget', '2', '--latency-ms', '0', '--local-registry'])
    v = '00'*31 + '01'
    def query(name, request):
        return ['--policy', str(private/f'{name}.json'), '--request-id', request, '--verifier', v]
    first = run('yes_real_stark', query('yes', 'r1'))
    (private/'yes.receipt').write_bytes(first)
    repeated = run('restart_cached_retry', query('yes', 'r1'))
    assert repeated == first
    run('changed_policy_retry_rejected', query('no', 'r1'), success=False)
    second = run('no_real_stark', query('no', 'r2'))
    (private/'no.receipt').write_bytes(second)
    assert run('restart_budget_exhausted', query('yes', 'r3')) == b'exhausted\n'
    assert run('retry_after_exhaustion', query('no', 'r2')) == second
    run('cap_increase_rejected', query('yes', 'r3') + ['--budget', '3'], success=False)
    run('reinitialization_rejected', ['--init', '--traces', str(ROOT/'work/n1_geolife.jsonl'), '--n', '32', '--budget', '99', '--latency-ms', '0', '--local-registry'], success=False)
    data = json.loads((wallet/'state.json').read_text())
    assert data['budget'] == 2 and data['scopes'][v]['next'] == 2
    requests = data['scopes'][v]['requests']
    # Wallet v4: the state commits to each receipt's SHA-256; bytes live in receipts/.
    for rid, expected in (('r1', first), ('r2', second)):
        digest = requests[rid]['response']
        assert digest == hashlib.sha256(expected).hexdigest()
        assert (wallet / 'receipts' / f'{digest}.bin').read_bytes() == expected
    result = {'cases': rows, 'all_passed': True, 'private_artifacts': str(private.relative_to(ROOT)),
              'receipt_bytes': [len(first), len(second)], 'identical_cached_retries': True,
              'receipt_sha256': [hashlib.sha256(b).hexdigest() for b in (first, second)],
              'registry_scope': 'randomized local registry, not ML-DSA admission'}
    (ROOT/'results/wallet_storage_smoke.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
