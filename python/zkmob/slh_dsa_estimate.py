"""Why not a standardised stateless signature? Cost of verifying SLH-DSA
(FIPS 205) INSIDE the proof, estimated by counting hash calls.

Unlinkability needs the device signature verified inside the proof (the
signature and public key are private), so the relevant cost is the
in-circuit verifier. In a circuit the private message digits force every
WOTS chain to be computed in full, so the count is the WORST case: len * (w-1)
chain steps per hypertree layer (the native average is half of that).

Counts per verification (FIPS 205, Algorithms 20 (FORS), 12/13 (WOTS/XMSS)):
  FORS         k leaf F + k*a auth H + one T_k over k*n bytes
  per layer    len*(w-1) chain F + one T_len over len*n bytes + h' auth H
  H_msg        about 4 blocks (digest + MGF1), PK.seed block 1 (it is private,
               so its SHA-2 midstate cannot be a public constant)
SHA-2 instantiation (Section 11.2): F uses SHA-256; for n = 16 all of H, T
also use SHA-256; for n = 24, 32 they use SHA-512. Block counts follow the
compressed-address input sizes (22-byte ADRS^c).

R1CS cost per compression is an ASSUMPTION (parameters below): about 27k
constraints for SHA-256 (circomlib / bellman gadgets report 25k to 30k) and
about 2.2x that for SHA-512. A non-standard Poseidon-instantiated SPHINCS+ is
also estimated (tweakable hash = Poseidon t = 5, 300 constraints/permutation,
measured formula 8*t*3 + R_P*3), to separate "standard hash" from
"stateless structure".

    PYTHONPATH=python python3 -m zkmob.slh_dsa_estimate
"""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

SHA256_R1CS = 27_000
SHA512_R1CS = 60_000
POSEIDON_T3 = 243          # measured in this code base (8*3*3 + 57*3)
POSEIDON_T5 = 300          # 8*5*3 + 60*3


@dataclass(frozen=True)
class SlhParams:
    name: str
    n: int
    h: int
    d: int
    hp: int
    a: int
    k: int
    lg_w: int
    m: int
    fips_sig_bytes: int     # FIPS 205, Table 2

    @property
    def w(self) -> int:
        return 1 << self.lg_w

    @property
    def length(self) -> int:
        len1 = math.ceil(8 * self.n / self.lg_w)
        len2 = math.floor(math.log2(len1 * (self.w - 1)) / self.lg_w) + 1
        return len1 + len2

    def sig_bytes(self) -> int:
        """FIPS 205: R + FORS (k(1+a)) + HT (h + d*len), in n-byte units."""
        return (1 + self.k * (1 + self.a) + self.h + self.d * self.length) * self.n


FIPS205 = [
    SlhParams("SLH-DSA-SHA2-128s", 16, 63, 7, 9, 12, 14, 4, 30, 7_856),
    SlhParams("SLH-DSA-SHA2-128f", 16, 66, 22, 3, 6, 33, 4, 34, 17_088),
    SlhParams("SLH-DSA-SHA2-192s", 24, 63, 7, 9, 14, 17, 4, 39, 16_224),
    SlhParams("SLH-DSA-SHA2-192f", 24, 66, 22, 3, 8, 33, 4, 42, 35_664),
    SlhParams("SLH-DSA-SHA2-256s", 32, 64, 8, 8, 14, 22, 4, 47, 29_792),
    SlhParams("SLH-DSA-SHA2-256f", 32, 68, 17, 4, 9, 35, 4, 49, 49_856),
]


def blocks(nbytes: int, block: int, pad: int) -> int:
    return math.ceil((nbytes + pad) / block)


def count(p: SlhParams) -> Dict[str, int]:
    big = p.n > 16                       # H, T, H_msg use SHA-512
    blk, pad = (128, 17) if big else (64, 9)
    adrs = 22
    f_calls = p.k + p.d * p.length * (p.w - 1)             # FORS leaves + all chain steps
    h_calls = p.k * p.a + p.d * p.hp                       # FORS + XMSS auth paths
    t_blocks = blocks(adrs + p.k * p.n, blk, pad) + p.d * blocks(adrs + p.length * p.n, blk, pad)
    sha256 = f_calls + 1 + (0 if big else h_calls + t_blocks + 4)
    sha512 = (h_calls + t_blocks + 4 + 1) if big else 0
    # Poseidon-instantiated SPHINCS+: F, H one/two t=5 permutations, T_l over l elements (+3 tag/ADRS)
    pos = f_calls * POSEIDON_T5 + h_calls * 2 * POSEIDON_T5 + (
        math.ceil((p.k + 3) / 4) + p.d * math.ceil((p.length + 3) / 4)) * POSEIDON_T5
    return {"f_calls": f_calls, "h_calls": h_calls, "t_blocks": t_blocks, "sha256_blocks": sha256,
            "sha512_blocks": sha512, "r1cs_sha2": sha256 * SHA256_R1CS + sha512 * SHA512_R1CS, "r1cs_poseidon_sphincs": pos}


def ours_reference() -> Dict[str, int]:
    """Measured hidden-signature layer of this design (Lamport t=3 + Merkle)."""
    lam, per_level, levels = 123_306, 483, 30
    try:
        with open("results/sig_bench.csv") as fh:
            lam = int(next(r for r in csv.DictReader(fh) if r["variant"] == "lamport_t3")["constraints"])
        with open("results/n4_linkability_breakdown.csv") as fh:
            per_level = int(next(csv.DictReader(fh))["merkle_per_level"])
    except (OSError, StopIteration, KeyError):
        pass
    return {"lamport": lam, "merkle": per_level * levels, "total": lam + per_level * levels, "levels": levels}


def main(out: str = "results/slh_dsa_estimate.csv") -> None:
    ref = ours_reference()
    rows: List[Dict] = []
    print(f"ours (stateful Lamport + epoch/registry paths, {ref['levels']} levels): {ref['total']:,} constraints "
          f"(Lamport {ref['lamport']:,} + Merkle {ref['merkle']:,})\n")
    print(f"{'parameter set':20} {'sig B':>6} {'SHA-256':>8} {'SHA-512':>8} {'R1CS (SHA-2)':>14} {'x ours':>7} "
          f"{'R1CS (Poseidon SPHINCS+)':>25} {'x ours':>7}")
    for p in FIPS205:
        assert p.sig_bytes() == p.fips_sig_bytes, p.name
        c = count(p)
        row = {"parameter_set": p.name, "n": p.n, "h": p.h, "d": p.d, "hp": p.hp, "a": p.a, "k": p.k, "w": p.w,
               "len": p.length, "sig_bytes": p.sig_bytes(), **c,
               "ratio_sha2_vs_ours": round(c["r1cs_sha2"] / ref["total"], 1),
               "ratio_poseidon_vs_ours": round(c["r1cs_poseidon_sphincs"] / ref["total"], 1),
               "ours_total": ref["total"], "sha256_r1cs_assumed": SHA256_R1CS, "sha512_r1cs_assumed": SHA512_R1CS}
        rows.append(row)
        print(f"{p.name:20} {p.sig_bytes():>6} {c['sha256_blocks']:>8,} {c['sha512_blocks']:>8,} "
              f"{c['r1cs_sha2']:>14,} {row['ratio_sha2_vs_ours']:>7} {c['r1cs_poseidon_sphincs']:>25,} "
              f"{row['ratio_poseidon_vs_ours']:>7}")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
