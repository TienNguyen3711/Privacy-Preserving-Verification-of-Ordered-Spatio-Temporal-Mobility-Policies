"""Regression for review R1 (1 Oct 2026): a crash between proof completion and
release must not let a retry release before the original deadline.

Real STARK prover, legacy (plaintext) storage so that the state can be read.
The first process is killed after its proof is ready (35 s, proving takes
about 23-33 s) but before the 60 s deadline; the retry resumes the same
request. Writes results/release_window_regression.json.

    python3 python/benchmarks/release_window_regression.py
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'zkvm/target/release/wallet_prove'
LATENCY_S, KILL_AT_S = 60, 35


def main():
    if 'RISC0_DEV_MODE' in os.environ:
        raise RuntimeError('unset RISC0_DEV_MODE')
    with tempfile.TemporaryDirectory(prefix='release-window-', dir=ROOT / 'work') as td:
        p = Path(td)
        wallet = p / 'wallet'
        subprocess.run([str(BINARY), '--legacy-plaintext', '--wallet', str(wallet), '--init', '--traces',
                        str(ROOT / 'work/n1_geolife.jsonl'), '--n', '32', '--budget', '2',
                        '--latency-ms', str(LATENCY_S * 1000)], check=True, capture_output=True)
        (p / 'policy.json').write_text(json.dumps({'steps': [{'zone': {'xmin': 0, 'xmax': 4294967295, 'ymin': 0,
                                                   'ymax': 4294967295}, 'max_gap': None}], 'avoid': None}))
        cmd = [str(BINARY), '--legacy-plaintext', '--wallet', str(wallet), '--policy', str(p / 'policy.json'),
               '--request-id', 'r', '--verifier', '01' * 32]
        start = time.monotonic()
        child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(KILL_AT_S)
        assert child.poll() is None, 'first process ended before the deadline'
        state = json.loads((wallet / 'state.json').read_text())
        req = state['scopes']['01' * 32]['requests']['r']
        stored_before_kill = req['response'] is not None
        child.kill()
        first_out, _ = child.communicate()
        retry = subprocess.run(cmd, capture_output=True, timeout=300)
        retry_done = time.monotonic() - start
        cached_start = time.monotonic()
        cached = subprocess.run(cmd, capture_output=True, timeout=60)
        result = {
            'latency_s': LATENCY_S, 'killed_at_s': KILL_AT_S,
            'response_stored_before_deadline': stored_before_kill,
            'first_process_stdout_bytes': len(first_out),
            'retry_exit': retry.returncode, 'retry_stdout_bytes': len(retry.stdout),
            'retry_released_at_s_since_first_start': retry_done,
            'released_before_original_deadline': retry_done < LATENCY_S,
            'cached_retry_identical': cached.stdout == retry.stdout, 'cached_retry_s': time.monotonic() - cached_start,
        }
        print(json.dumps(result, indent=2))
        assert not stored_before_kill and len(first_out) == 0
        assert retry.returncode == 0 and len(retry.stdout) > 100_000
        assert not result['released_before_original_deadline'] and result['cached_retry_identical']
        (ROOT / 'results/release_window_regression.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
