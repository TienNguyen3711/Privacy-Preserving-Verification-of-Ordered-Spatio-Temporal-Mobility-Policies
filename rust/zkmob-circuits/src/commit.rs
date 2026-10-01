//! Poseidon commitment to a trajectory. This is the value a device would sign.
//!
//! * `Commit::Binding`   C = Poseidon(T). Deterministic, so equal traces give
//!   equal commitments. This is baseline B2 (Bogdanov et al. 2025, trail hash
//!   as a public input), which is what makes proofs linkable (claim N4).
//! * `Commit::Hiding(r)` C = Poseidon(r || T) with a fresh 128-bit blinding r
//!   chosen by the device. Hiding in the random-oracle model for Poseidon;
//!   binding under collision resistance. Cost: one extra absorbed element.
//!
//! Hiding alone does NOT make proofs unlinkable: every proof about the same
//! signed trace still shows the same C. Unlinkability needs C (and the
//! signature on it) to move into the witness, which is roadmap step 6.

use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::types::Point;

/// How a circuit binds the private trajectory to a public commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// No commitment (policy cost only).
    Off,
    /// C = Poseidon(T): binding, not hiding (baseline B2).
    Binding,
    /// C = Poseidon(r || T): binding and hiding, r is the blinding value.
    Hiding(u128),
}

impl Commit {
    pub fn is_on(&self) -> bool {
        !matches!(self, Commit::Off)
    }

    /// Fresh hiding commitment mode with a random 128-bit blinding value.
    pub fn fresh_hiding<R: ark_std::rand::Rng>(rng: &mut R) -> Self {
        Commit::Hiding(rng.r#gen::<u128>())
    }

    /// The public commitment value, or `None` when off.
    pub fn value<F: PrimeField + Absorb>(&self, traj: &[Point]) -> Option<F> {
        let cfg = poseidon_config::<F>();
        match self {
            Commit::Off => None,
            Commit::Binding => Some(commit_native(&cfg, traj)),
            Commit::Hiding(r) => Some(commit_native_hiding(&cfg, traj, *r)),
        }
    }
}

/// Poseidon over BN254 scalar field: alpha = 5, 8 full rounds, 57 partial
/// rounds, rate 2, capacity 1 (standard 128-bit parameters for this field).
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
    PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
}

pub fn flatten<F: PrimeField>(traj: &[Point]) -> Vec<F> {
    traj.iter().flat_map(|p| [F::from(p.x), F::from(p.y), F::from(p.t)]).collect()
}

pub fn commit_native<F: PrimeField + Absorb>(cfg: &PoseidonConfig<F>, traj: &[Point]) -> F {
    let mut s = PoseidonSponge::<F>::new(cfg);
    s.absorb(&flatten::<F>(traj));
    s.squeeze_field_elements::<F>(1)[0]
}

/// C = Poseidon(r || T). The blinding value is absorbed first.
pub fn commit_native_hiding<F: PrimeField + Absorb>(cfg: &PoseidonConfig<F>, traj: &[Point], r: u128) -> F {
    let mut v = vec![F::from(r)];
    v.extend(flatten::<F>(traj));
    let mut s = PoseidonSponge::<F>::new(cfg);
    s.absorb(&v);
    s.squeeze_field_elements::<F>(1)[0]
}

/// Absorb already-allocated trajectory variables and return the digest.
pub fn commit_gadget<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    vars: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut s = PoseidonSpongeVar::<F>::new(cs, cfg);
    s.absorb(&vars.to_vec())?;
    Ok(s.squeeze_field_elements(1)?.remove(0))
}

/// Allocate the public commitment and enforce it against the private
/// trajectory variables `flat` = [x0, y0, t0, x1, ...]. For `Hiding`, the
/// blinding value is a private witness absorbed before the trajectory.
pub fn enforce_commitment<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    mode: Commit,
    traj: &[Point],
    flat: Vec<FpVar<F>>,
) -> Result<(), SynthesisError> {
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    let Some(c) = mode.value::<F>(traj) else { return Ok(()) };
    let c = FpVar::new_input(cs.clone(), || Ok(c))?;
    let vars = match mode {
        Commit::Hiding(r) => {
            let rv = FpVar::new_witness(cs.clone(), || Ok(F::from(r)))?;
            let mut v = vec![rv];
            v.extend(flat);
            v
        }
        _ => flat,
    };
    let h = commit_gadget(cs, &poseidon_config::<F>(), &vars)?;
    h.enforce_equal(&c)
}
