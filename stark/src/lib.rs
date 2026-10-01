//! Plonky3 (hash-based, zero-knowledge STARK) components of the relation.
//!
//! * `ScanAir`: the policy scan (proves "holds" or "does not hold" exactly),
//!   one trace row per fix, over BabyBear. Same algorithm as
//!   `zkmob_core::scan_eval` / rust `budget::enforce_scan_policy`.
//! * `zk_config`: uni-stark with `HidingFriPcs` (random codewords + hiding
//!   Merkle commitments), i.e. Plonky3's zero-knowledge mode, and
//!   `FriParameters::new_benchmark_zk` (blowup 4, 100 queries, 16-bit PoW).
//!
//! Value ranges (BabyBear has a 31-bit modulus): coordinates < 2^16 m (a
//! 65 km window, enough for the city windows used), times < 2^24 s.
//!
//! Row layout (see `Layout`): active flag; x, y, t and their bits; per zone
//! (policy steps, then the avoid zone) four comparison decompositions and
//! the in-zone products; per later step a gap comparison and the "ok" flag;
//! per step hit / has / last; the avoidance flag; sort bits.
//! Row j holds the scan state AFTER fix j; transitions implement
//!   hit'_s = active' * inzone'_s * ok'_s,  ok'_s = has_{s-1} * [t' - last_{s-1} <= gap_s]
//!   has'_s = has_s OR hit'_s,  last'_s = hit'_s ? t' : last_s
//! using the PREVIOUS row's state for step s - 1, so one fix cannot serve
//! two steps. Padding rows are inactive and repeat the last timestamp.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zkmob_core::{Point, Policy};

pub const CB: usize = 16; // coordinate bits
pub const TB: usize = 24; // time bits

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
pub type ValMmcs = MerkleTreeHidingMmcs<[Val; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN], FieldHash, Compress, StdRng, 2, 4, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = p3_dft::Radix2DitParallel<Val>;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
pub type ZkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Fresh prover randomness (hiding requires it to be secret and unpredictable).
pub fn os_rng() -> StdRng {
    let mut seed = [0u8; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut seed).unwrap();
    StdRng::from_seed(seed)
}

/// Zero-knowledge STARK configuration (Keccak Merkle commitments, hiding FRI).
pub fn zk_config() -> ZkConfig {
    let u64_hash = U64Hash::new(KeccakF {});
    let val_mmcs = ValMmcs::new(FieldHash::new(u64_hash), Compress::new(u64_hash), 0, os_rng());
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri = FriParameters::new_benchmark_zk(challenge_mmcs);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, 4, os_rng());
    ZkConfig::new(pcs, Challenger::from_hasher(vec![], ByteHash {}))
}

/// Column offsets.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub k: usize,
    pub avoid: bool,
}

const CMP: usize = CB + 1; // bits per coordinate comparison
const ZONE_W: usize = 4 * CMP + 3; // 4 comparisons + inx, iny, inz
const GAP_W: usize = TB + 1 + 1; // decomposition + ok

impl Layout {
    pub const ACTIVE: usize = 0;
    pub const X: usize = 1;
    pub const Y: usize = 2;
    pub const T: usize = 3;
    pub const XB: usize = 4;
    pub const YB: usize = Self::XB + CB;
    pub const TBITS: usize = Self::YB + CB;
    const ZONES: usize = Self::TBITS + TB;

    pub fn zones(&self) -> usize {
        self.k + self.avoid as usize
    }
    /// Start of zone z's block: 4 x CMP comparison bits, then inx, iny, inz.
    pub fn zone(&self, z: usize) -> usize {
        Self::ZONES + z * ZONE_W
    }
    pub fn inz(&self, z: usize) -> usize {
        self.zone(z) + 4 * CMP + 2
    }
    /// Gap block of step s >= 1: TB + 1 bits, then ok.
    pub fn gap(&self, s: usize) -> usize {
        self.zone(self.zones()) + (s - 1) * GAP_W
    }
    pub fn ok(&self, s: usize) -> usize {
        self.gap(s) + TB + 1
    }
    fn state(&self) -> usize {
        self.gap(self.k)
    }
    pub fn hit(&self, s: usize) -> usize {
        self.state() + 3 * s
    }
    pub fn has(&self, s: usize) -> usize {
        self.state() + 3 * s + 1
    }
    pub fn last(&self, s: usize) -> usize {
        self.state() + 3 * s + 2
    }
    pub fn viol(&self) -> usize {
        self.state() + 3 * self.k
    }
    pub fn sort(&self) -> usize {
        self.viol() + 1
    }
    pub fn width(&self) -> usize {
        self.sort() + TB
    }
    /// Public values: per step xmin, xmax, ymin, ymax, has_gap, gap; then
    /// the avoid box (if any); then the outcome.
    pub fn num_public(&self) -> usize {
        6 * self.k + 4 * self.avoid as usize + 1
    }
}

pub struct ScanAir {
    pub layout: Layout,
}

impl<F> BaseAir<F> for ScanAir {
    fn width(&self) -> usize {
        self.layout.width()
    }
    fn num_public_values(&self) -> usize {
        self.layout.num_public()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

/// sum_i bits[i] * 2^i
fn recompose<AB: AirBuilder>(row: &[AB::Var], start: usize, n: usize) -> AB::Expr {
    (0..n).fold(AB::Expr::ZERO, |acc, i| acc + AB::Expr::from(row[start + i]) * AB::Expr::from_u64(1u64 << i))
}

impl<AB: AirBuilder> Air<AB> for ScanAir {
    fn eval(&self, builder: &mut AB) {
        let l = self.layout;
        let main = builder.main();
        let (loc, nxt): (Vec<AB::Var>, Vec<AB::Var>) = (main.current_slice().to_vec(), main.next_slice().to_vec());
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|&p| p.into()).collect();
        let v = |row: &[AB::Var], i: usize| -> AB::Expr { row[i].into() };
        let one = AB::Expr::ONE;
        let zone_bounds = |z: usize| -> [AB::Expr; 4] {
            let base = if z < l.k { 6 * z } else { 6 * l.k };
            [pis[base].clone(), pis[base + 1].clone(), pis[base + 2].clone(), pis[base + 3].clone()]
        };

        // ---- per-row constraints (every row) ----
        for row in [&loc] {
            builder.assert_bool(v(row, Layout::ACTIVE));
            for (col, bits, n) in [(Layout::X, Layout::XB, CB), (Layout::Y, Layout::YB, CB), (Layout::T, Layout::TBITS, TB)] {
                for i in 0..n {
                    builder.assert_bool(v(row, bits + i));
                }
                builder.assert_eq(v(row, col), recompose::<AB>(row, bits, n));
            }
            for z in 0..l.zones() {
                let b = zone_bounds(z);
                let base = l.zone(z);
                let two = AB::Expr::from_u64(1u64 << CB);
                // d0 = x - xmin, d1 = xmax - x, d2 = y - ymin, d3 = ymax - y (each + 2^CB)
                let diffs = [
                    v(row, Layout::X) - b[0].clone(),
                    b[1].clone() - v(row, Layout::X),
                    v(row, Layout::Y) - b[2].clone(),
                    b[3].clone() - v(row, Layout::Y),
                ];
                for (c, d) in diffs.into_iter().enumerate() {
                    let off = base + c * CMP;
                    for i in 0..CMP {
                        builder.assert_bool(v(row, off + i));
                    }
                    builder.assert_eq(recompose::<AB>(row, off, CMP), d + two.clone());
                }
                let top = |c: usize| v(row, base + c * CMP + CB);
                builder.assert_eq(v(row, base + 4 * CMP), top(0) * top(1));
                builder.assert_eq(v(row, base + 4 * CMP + 1), top(2) * top(3));
                builder.assert_eq(v(row, l.inz(z)), v(row, base + 4 * CMP) * v(row, base + 4 * CMP + 1));
            }
            for s in 1..l.k {
                for i in 0..=TB {
                    builder.assert_bool(v(row, l.gap(s) + i));
                }
            }
            for i in 0..TB {
                builder.assert_bool(v(row, l.sort() + i));
            }
            // hit_s = active * inz_s * (s == 0 ? 1 : ok_s)
            for s in 0..l.k {
                let base = v(row, Layout::ACTIVE) * v(row, l.inz(s));
                let rhs = if s == 0 { base } else { base * v(row, l.ok(s)) };
                builder.assert_eq(v(row, l.hit(s)), rhs);
            }
        }

        let gap_pub = |s: usize| (pis[6 * s + 4].clone(), pis[6 * s + 5].clone()); // (has_gap, gap)
        let two_t = AB::Expr::from_u64(1u64 << TB);
        let avoid_hit = |row: &[AB::Var]| v(row, Layout::ACTIVE) * v(row, l.inz(l.k));

        // ---- first row ----
        {
            let mut b = builder.when_first_row();
            b.assert_one(v(&loc, Layout::ACTIVE));
            for s in 0..l.k {
                b.assert_eq(v(&loc, l.has(s)), v(&loc, l.hit(s)));
                b.assert_eq(v(&loc, l.last(s)), v(&loc, l.hit(s)) * v(&loc, Layout::T));
                if s >= 1 {
                    let (_, gap) = gap_pub(s);
                    b.assert_zero(v(&loc, l.ok(s)));
                    b.assert_eq(recompose::<AB>(&loc, l.gap(s), TB + 1), gap - v(&loc, Layout::T) + two_t.clone());
                }
            }
            if l.avoid {
                b.assert_eq(v(&loc, l.viol()), avoid_hit(&loc));
            } else {
                b.assert_zero(v(&loc, l.viol()));
            }
        }

        // ---- transitions ----
        {
            let mut b = builder.when_transition();
            // active: 1...1 0...0
            b.assert_zero(v(&nxt, Layout::ACTIVE) * (one.clone() - v(&loc, Layout::ACTIVE)));
            // time-sorted between active rows: t' - t = sum sortbits'
            b.assert_zero(v(&nxt, Layout::ACTIVE) * (v(&nxt, Layout::T) - v(&loc, Layout::T) - recompose::<AB>(&nxt, l.sort(), TB)));
            for s in 0..l.k {
                if s >= 1 {
                    let (has_gap, gap) = gap_pub(s);
                    // [t' - last_{s-1} <= gap] is the top bit of gap - (t' - last) + 2^TB
                    b.assert_eq(
                        recompose::<AB>(&nxt, l.gap(s), TB + 1),
                        gap - (v(&nxt, Layout::T) - v(&loc, l.last(s - 1))) + two_t.clone(),
                    );
                    let leq = v(&nxt, l.gap(s) + TB);
                    let cond = has_gap.clone() * leq + (one.clone() - has_gap);
                    b.assert_eq(v(&nxt, l.ok(s)), v(&loc, l.has(s - 1)) * cond);
                }
                let (h, hn) = (v(&loc, l.has(s)), v(&nxt, l.hit(s)));
                b.assert_eq(v(&nxt, l.has(s)), h.clone() + hn.clone() - h * hn.clone());
                b.assert_eq(v(&nxt, l.last(s)), hn.clone() * v(&nxt, Layout::T) + (one.clone() - hn) * v(&loc, l.last(s)));
            }
            if l.avoid {
                let (vi, a) = (v(&loc, l.viol()), avoid_hit(&nxt));
                b.assert_eq(v(&nxt, l.viol()), vi.clone() + a.clone() - vi * a);
            } else {
                b.assert_zero(v(&nxt, l.viol()));
            }
        }

        // ---- last row: public outcome ----
        builder
            .when_last_row()
            .assert_eq(pis[l.num_public() - 1].clone(), v(&loc, l.has(l.k - 1)) * (one - v(&loc, l.viol())));
    }
}

/// Public values for a policy and claimed outcome.
pub fn public_values(policy: &Policy, outcome: bool) -> Vec<Val> {
    let f = |x: u32| Val::from_u64(x as u64);
    let mut out = Vec::new();
    for s in &policy.steps {
        out.extend([f(s.zone.xmin), f(s.zone.xmax), f(s.zone.ymin), f(s.zone.ymax)]);
        out.extend([f(s.max_gap.is_some() as u32), f(s.max_gap.unwrap_or(0))]);
    }
    if let Some(z) = &policy.avoid {
        out.extend([f(z.xmin), f(z.xmax), f(z.ymin), f(z.ymax)]);
    }
    out.push(Val::from_bool(outcome));
    out
}

/// Minimum trace height: Plonky3's hiding FRI needs mask height >=
/// 2 * (extension degree * opening points + queries) = 2 * (4 + 100) = 208
/// rows of the committed trace, so 256 rows. Padding (inactive
/// rows) also hides the exact number of fixes up to the padded height.
pub const MIN_ROWS: usize = 256;

/// Honest trace (rows = next power of two >= max(n, MIN_ROWS)).
pub fn generate_trace(traj: &[Point], policy: &Policy) -> RowMajorMatrix<Val> {
    let l = Layout { k: policy.steps.len(), avoid: policy.avoid.is_some() };
    let n = traj.len();
    assert!(n >= 1);
    let rows = n.next_power_of_two().max(MIN_ROWS);
    let w = l.width();
    let mut m = vec![Val::ZERO; rows * w];
    let f = |x: u64| Val::from_u64(x);
    let set_bits = |row: &mut [Val], start: usize, val: u64, n: usize| {
        for i in 0..n {
            row[start + i] = f((val >> i) & 1);
        }
    };
    let zones: Vec<zkmob_core::BoxZone> = policy.steps.iter().map(|s| s.zone).chain(policy.avoid).collect();
    let mut has = vec![false; l.k];
    let mut last = vec![0u32; l.k];
    let mut viol = false;
    let mut prev_t = 0u32;
    let t_last = traj[n - 1].t;
    for r in 0..rows {
        let row = &mut m[r * w..(r + 1) * w];
        let active = r < n;
        let p = if active { traj[r] } else { Point { x: 0, y: 0, t: t_last } };
        assert!(p.x < 1 << CB && p.y < 1 << CB && (p.t as u64) < 1 << TB, "value out of AIR range");
        row[Layout::ACTIVE] = f(active as u64);
        row[Layout::X] = f(p.x as u64);
        row[Layout::Y] = f(p.y as u64);
        row[Layout::T] = f(p.t as u64);
        set_bits(row, Layout::XB, p.x as u64, CB);
        set_bits(row, Layout::YB, p.y as u64, CB);
        set_bits(row, Layout::TBITS, p.t as u64, TB);
        let mut inz = vec![false; zones.len()];
        for (z, zb) in zones.iter().enumerate() {
            let base = l.zone(z);
            let two = 1i64 << CB;
            let d = [p.x as i64 - zb.xmin as i64, zb.xmax as i64 - p.x as i64, p.y as i64 - zb.ymin as i64, zb.ymax as i64 - p.y as i64];
            let mut top = [false; 4];
            for c in 0..4 {
                let val = (d[c] + two) as u64;
                set_bits(row, base + c * CMP, val, CMP);
                top[c] = (val >> CB) & 1 == 1;
            }
            row[base + 4 * CMP] = f((top[0] && top[1]) as u64);
            row[base + 4 * CMP + 1] = f((top[2] && top[3]) as u64);
            inz[z] = top.iter().all(|&b| b);
            row[l.inz(z)] = f(inz[z] as u64);
        }
        // scan step (uses previous-row state)
        let mut hit = vec![false; l.k];
        for s in 0..l.k {
            let ok = if s == 0 {
                true
            } else {
                let gap = policy.steps[s].max_gap.unwrap_or(0) as i64;
                let lastp = if r == 0 { 0 } else { last[s - 1] as i64 };
                let val = (gap - (p.t as i64 - lastp) + (1i64 << TB)) as u64;
                set_bits(row, l.gap(s), val, TB + 1);
                let leq = (val >> TB) & 1 == 1;
                let okv = r > 0 && has[s - 1] && (policy.steps[s].max_gap.is_none() || leq);
                row[l.ok(s)] = f(okv as u64);
                okv
            };
            hit[s] = active && inz[s] && ok;
        }
        for s in 0..l.k {
            has[s] |= hit[s];
            if hit[s] {
                last[s] = p.t;
            }
            row[l.hit(s)] = f(hit[s] as u64);
            row[l.has(s)] = f(has[s] as u64);
            row[l.last(s)] = f(last[s] as u64);
        }
        if l.avoid {
            viol |= active && inz[l.k];
        }
        row[l.viol()] = f(viol as u64);
        if r > 0 && active {
            set_bits(row, l.sort(), (p.t - prev_t) as u64, TB);
        }
        prev_t = p.t;
    }
    RowMajorMatrix::new(m, w)
}
