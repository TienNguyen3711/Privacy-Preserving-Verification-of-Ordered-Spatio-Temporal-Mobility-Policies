"""Global registry end to end (review R3): wallets of different devices share
one ML-DSA-admitted registry root, so verified presentations carry no
per-wallet identifier; wallets with a LOCAL registry (negative control) are
linked by their root.

Real STARK receipts; each presentation is inspected exactly as a verifier
sees it (`registry inspect-receipt`: verified journal). Two presentations are
linked if they share any public value that is not common to all
presentations (as in the N4 experiment). Writes
results/global_registry_smoke.json.

    python3 python/benchmarks/global_registry_smoke.py
"""
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'zkvm/target/release'
TRACES = str(ROOT / 'work/n1_geolife.jsonl')
VERIFIER = '00' * 31 + '07'


def sh(*args, ok=True):
    p = subprocess.run([str(a) for a in args], capture_output=True)
    assert (p.returncode == 0) == ok, p.stderr.decode(errors='replace')
    return p.stdout


def linkage(pres):
    """Share of pairs linked by a shared non-universal public value."""
    keys = ('reg_root', 'nullifier')
    universal = {k for k in keys if len({p['view'][k] for p in pres}) == 1}
    out = {'same_trip': [0, 0], 'same_device_other_trip': [0, 0], 'other_device': [0, 0]}
    for a, b in itertools.combinations(pres, 2):
        kind = ('same_trip' if a['wallet'] == b['wallet'] else
                'same_device_other_trip' if a['device'] == b['device'] else 'other_device')
        linked = any(a['view'][k] == b['view'][k] for k in keys if k not in universal)
        out[kind][0] += linked
        out[kind][1] += 1
    return {k: (v[0] / v[1] if v[1] else None, v[1]) for k, v in out.items()}, sorted(universal)


def main():
    if 'RISC0_DEV_MODE' in os.environ:
        raise RuntimeError('unset RISC0_DEV_MODE')
    with tempfile.TemporaryDirectory(prefix='global-registry-', dir=ROOT / 'work') as td:
        d = Path(td)
        reg = BIN / 'registry'
        sh(reg, 'manufacturer', '--out', d / 'mfr.secret', '--public', d / 'mfr.pub')
        for i in range(4):
            sh(reg, 'device', '--manufacturer', d / 'mfr.secret', '--out', d / f'dev{i}.secret',
               '--request', d / f'dev{i}.req', '--epoch-depth', '10')
        reqs = [d / f'dev{i}.req' for i in range(4)]
        built = json.loads(sh(reg, 'build', '--manufacturer-pub', d / 'mfr.pub', '--depth', '20',
                              '--out', d / 'registry.json', *reqs))
        # A forged admission (root changed after signing) is rejected.
        forged = json.loads((d / 'dev0.req').read_text())
        forged['root'][0] ^= 1
        (d / 'forged.req').write_text(json.dumps(forged))
        sh(reg, 'build', '--manufacturer-pub', d / 'mfr.pub', '--depth', '20', '--out', d / 'x.json',
           d / 'forged.req', ok=False)

        policies = {
            'yes': {'steps': [{'zone': {'xmin': 0, 'xmax': 4294967295, 'ymin': 0, 'ymax': 4294967295},
                               'max_gap': None}], 'avoid': None},
            'no': {'steps': [{'zone': {'xmin': 4294967295, 'xmax': 4294967295, 'ymin': 4294967295,
                                       'ymax': 4294967295}, 'max_gap': None}], 'avoid': None},
        }
        for name, pol in policies.items():
            (d / f'{name}.json').write_text(json.dumps(pol))

        def wallet(name, device, k, global_reg):
            extra = ['--device', d / f'dev{device}.secret', '--registry', d / 'registry.json'] if global_reg else ['--local-registry']
            sh(BIN / 'wallet_prove', '--legacy-plaintext', '--wallet', d / name, '--init', '--traces', TRACES,
               '--n', '32', '--budget', '2', '--latency-ms', '0', '--trace-index', k, *extra)
            pres = []
            for pol in ('yes', 'no'):
                out = sh(BIN / 'wallet_prove', '--legacy-plaintext', '--wallet', d / name, '--policy',
                         d / f'{pol}.json', '--request-id', pol, '--verifier', VERIFIER)
                (d / f'{name}-{pol}.bin').write_bytes(out)
                view = json.loads(sh(reg, 'inspect-receipt', '--receipt', d / f'{name}-{pol}.bin'))
                assert view['outcome'] == (pol == 'yes')
                pres.append({'wallet': name, 'device': device, 'view': view})
            return pres

        # Device 0 records two trips; devices 1-3 one trip each.
        plan = [('g0a', 0, 0), ('g0b', 0, 1), ('g1', 1, 2), ('g2', 2, 3), ('g3', 3, 4)]
        global_pres = [p for w in plan for p in wallet(*w, True)]
        local_pres = [p for w in [('l0', 0, 0), ('l1', 1, 1)] for p in wallet(*w, False)]
        dev0 = json.loads((d / 'dev0.secret').read_text())

        g_link, g_universal = linkage(global_pres)
        l_link, l_universal = linkage(local_pres)
        result = {
            'devices': 4, 'wallets': len(plan), 'presentations': len(global_pres),
            'registry_root': built['root'],
            'all_global_roots_equal_registry_root': all(p['view']['reg_root'] == built['root'] for p in global_pres),
            'global_nullifiers_distinct': len({p['view']['nullifier'] for p in global_pres}) == len(global_pres),
            'global_linkage': g_link, 'global_universal_fields': g_universal,
            'local_control_linkage': l_link, 'local_control_universal_fields': l_universal,
            'device0_next_leaf_after_two_trips': dev0['next_leaf'],
            'forged_admission_rejected': True,
        }
        print(json.dumps(result, indent=2))
        assert result['all_global_roots_equal_registry_root'] and result['global_nullifiers_distinct']
        assert all(v[0] == 0 for v in g_link.values() if v[0] is not None)
        assert l_link['same_trip'][0] == 1.0 and l_link['other_device'][0] == 0.0
        assert dev0['next_leaf'] == 2
        (ROOT / 'results/global_registry_smoke.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
