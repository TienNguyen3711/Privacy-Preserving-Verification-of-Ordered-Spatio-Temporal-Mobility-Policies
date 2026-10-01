"""Real-prover integration with encrypted storage and a separate ledger process."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    if 'RISC0_DEV_MODE' in os.environ:
        raise RuntimeError('unset RISC0_DEV_MODE')
    private = Path(tempfile.mkdtemp(prefix='protected-wallet-', dir=ROOT/'work'))
    binary = ROOT/'zkvm/target/release/wallet_prove'
    script = ROOT/'python/zkmob/anchor_service.py'
    for name in ('key', 'short-key', 'token'):
        subprocess.run([str(binary), '--generate-key', str(private/name)], check=True)
    subprocess.run(['python3', str(script), '--init', '--state-dir', str(private/'ledger')], check=True)
    service = subprocess.Popen(['python3', str(script), '--state-dir', str(private/'ledger'),
                                '--token-file', str(private/'token'), '--port', '0'], stdout=subprocess.PIPE)
    try:
        port = json.loads(service.stdout.readline())['port']
        opts = ['--anchor-token', str(private/'token'),
                '--anchor-url', f'http://127.0.0.1:{port}', '--allow-loopback-http']
        rows = []
        def run(label, args, success=True, wallet='wallet'):
            start = time.perf_counter()
            # Each wallet has its own key and hence its own ledger identity.
            key = ['--key-file', str(private/('short-key' if wallet == 'short' else 'key'))]
            p = subprocess.run([str(binary), '--wallet', str(private/wallet), *opts, *key, *args], capture_output=True, timeout=180)
            assert (p.returncode == 0) == success, p.stderr.decode(errors='replace')
            if not success:
                assert p.stdout == b'', f'{label}: failure leaked stdout bytes'
            elapsed = time.perf_counter()-start
            with sqlite3.connect((private/'ledger/ledger.sqlite').as_uri() + '?mode=ro', uri=True) as db:
                events, identities = db.execute('SELECT count(*), count(DISTINCT wallet_id) FROM events').fetchone()
                revision = db.execute('SELECT max(revision) FROM heads').fetchone()[0]
            snapshot = private/wallet/'state.enc'
            rows.append({'case': label, 'wallet': wallet, 'exit_code': p.returncode, 'wall_s': elapsed,
                         'stdout_bytes': len(p.stdout), 'ledger_events': events,
                         'ledger_identities': identities, 'ledger_revision': revision,
                         'encrypted_snapshot_bytes': snapshot.stat().st_size if snapshot.exists() else None})
            print(label, f"{rows[-1]['wall_s']:.2f}s", flush=True)
            return p.stdout
        latency_s = 45.0  # fixed release latency, above the observed ~23-29 s proving time
        run('initialize_encrypted_wallet', ['--init', '--traces', str(ROOT/'work/n1_geolife.jsonl'), '--n', '32', '--budget', '2',
                                            '--latency-ms', str(int(latency_s * 1000))])
        shutil.copytree(private/'wallet', private/'clone')
        policy = {'steps': [{'zone': {'xmin': 0, 'xmax': 4294967295, 'ymin': 0, 'ymax': 4294967295}, 'max_gap': None}], 'avoid': None}
        (private/'policy.json').write_text(json.dumps(policy))
        query = ['--policy', str(private/'policy.json'), '--request-id', 'r1', '--verifier', '00'*31+'01']
        receipt = run('encrypted_real_stark', query)
        assert run('restart_identical_cached_receipt', query) == receipt
        run('stale_clone_rejected', query, False, 'clone')
        no_policy = {'steps': [{'zone': {'xmin': 4294967295, 'xmax': 4294967295, 'ymin': 4294967295, 'ymax': 4294967295}, 'max_gap': None}], 'avoid': None}
        (private/'no.json').write_text(json.dumps(no_policy))
        no_query = ['--policy', str(private/'no.json'), '--request-id', 'no', '--verifier', '00'*31+'01']
        no_receipt = run('protected_no_real_stark', no_query)
        assert run('restart_identical_no_receipt', no_query) == no_receipt
        run('changed_policy_rejected_empty_stdout', [*no_query[:2], *query[2:]], False)
        assert run('budget_exhausted', [*query[:-4], '--request-id', 'r2', '--verifier', '00'*31+'01']) == b'exhausted\n'
        assert not (private/'wallet/state.json').exists()
        # Fixed-latency release: fresh yes and no answers leave at admission + latency.
        by_case = {row['case']: row for row in rows}
        fresh = [by_case['encrypted_real_stark']['wall_s'], by_case['protected_no_real_stark']['wall_s']]
        assert all(latency_s <= w <= latency_s + 5.0 for w in fresh), fresh
        # Overrun: a wallet whose latency is below the proving time expires the request.
        run('initialize_short_latency_wallet', ['--init', '--traces', str(ROOT/'work/n1_geolife.jsonl'), '--n', '32',
                                                '--budget', '2', '--latency-ms', '1000'], wallet='short')
        assert run('overrun_expires_without_release', query, wallet='short') == b'expired\n'
        assert run('expired_retry_never_releases', query, wallet='short') == b'expired\n'
        other = [*query[:2], '--request-id', 'r-other', '--verifier', '00'*31+'01']
        assert run('second_overrun_expires', other, wallet='short') == b'expired\n'
        assert run('expired_slots_not_refunded', [*query[:2], '--request-id', 'r-third', '--verifier', '00'*31+'01'],
                   wallet='short') == b'exhausted\n'
        service.terminate(); service.wait(timeout=10)
        run('offline_cached_receipt_rejected', query, False)
        result = {'all_passed': True, 'cases': rows, 'receipt_bytes': [len(receipt), len(no_receipt)], 'failure_stdout_empty': True,
                  'private_artifacts': str(private.relative_to(ROOT)),
                  'scope': 'local integration; separate ledger process, not an independent production host'}
        by_case = {row['case']: row for row in rows}
        result['release_latency_s'] = latency_s
        result['fresh_release_wall_s'] = {'yes': by_case['encrypted_real_stark']['wall_s'],
                                          'no': by_case['protected_no_real_stark']['wall_s']}
        assert by_case['encrypted_real_stark']['ledger_events'] == 3
        assert by_case['protected_no_real_stark']['ledger_events'] == 5
        # ledger_identities counts the whole ledger: one identity until the short wallet registers.
        cut = next(i for i, row in enumerate(rows) if row['wallet'] == 'short')
        assert all(row['ledger_identities'] == 1 for row in rows[:cut])
        assert all(row['ledger_identities'] == 2 for row in rows[cut:])
        result['overrun_outputs'] = ['expired', 'expired', 'expired', 'exhausted']
        # Condition (iv): an overrun costs the same two ledger commits as an answer.
        assert by_case['overrun_expires_without_release']['ledger_events'] - \
            by_case['initialize_short_latency_wallet']['ledger_events'] == 2
        assert by_case['second_overrun_expires']['ledger_events'] - \
            by_case['expired_retry_never_releases']['ledger_events'] == 2
        result['overrun_ledger_commits_per_request'] = 2
        # Overruns are reported at the deadline itself (1 s), not when proving ends.
        result['overrun_status_wall_s'] = [by_case['overrun_expires_without_release']['wall_s'],
                                           by_case['second_overrun_expires']['wall_s']]
        assert all(w < 1.0 + 3.0 for w in result['overrun_status_wall_s']), result['overrun_status_wall_s']
        assert by_case['restart_identical_cached_receipt']['ledger_events'] == 3
        assert by_case['restart_identical_no_receipt']['ledger_events'] == 5
        metadata = {'observations': rows, 'stable_identity_visible_to_ledger': True,
                    'new_answer_adds_two_commits': True, 'cached_retry_adds_no_commit': True,
                    'limits': 'Single local run; wall times and snapshot sizes are client/storage observations, not ledger timing measurements. No mutual-information estimate or timing classifier. Ledger request timing is not captured.'}
        (ROOT/'results/wallet_metadata_observations.json').write_text(json.dumps(metadata, indent=2)+'\n')
        (ROOT/'results/wallet_protection_smoke.json').write_text(json.dumps(result, indent=2)+'\n')
    finally:
        if service.poll() is None:
            service.terminate(); service.wait(timeout=10)


if __name__ == '__main__':
    main()
