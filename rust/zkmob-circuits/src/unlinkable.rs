//! Unlinkable policy proof (roadmap step 6, claim N4).
//!
//! Public:  policy parameters, registry root R.
//! Witness: trajectory T, blinding r, device signature (Lamport reveal /
//!          other halves, leaf index, device-tree path), registry index and
//!          path, witness indices for the policy.
//! Relation:
//!   C      = Poseidon(r || T)                          (hiding commitment)
//!   leaf   = LamportPK(C, reveal, other)               (device signed C)
//!   E      = MerkleRoot(leaf, leaf index, epoch path)  (epoch subtree root)
//!   R      = MerkleRoot(E, reg. index, reg. path)      (epoch is registered)
//!   T satisfies the policy                             (as in `ordered.rs`)
//!
//! Nothing trace- or device-specific is public, so two proofs about the same
//! trace (or the same device) share no value other than the policy and R;
//! with a zero-knowledge proof system they are unlinkable beyond what the
//! policies and their outcomes reveal (that residual leakage is N5).

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::commit::{commit_gadget, commit_native_hiding, poseidon_config};
use crate::ordered::{alloc_policy, alloc_trajectory, enforce_policy, flatten_vars, policy_public_inputs};
use crate::sig::{alloc_index_bits, merkle_root_gadget, ots_pk_hash_gadget, DeviceSig};
use crate::types::{BoxZone, Point, Step};

#[derive(Clone)]
pub struct UnlinkableCircuit<F: PrimeField> {
    pub traj: Vec<Point>,
    pub steps: Vec<Step>,
    pub avoid: Option<BoxZone>,
    pub witness: Option<Vec<usize>>,
    /// Blinding value of the hiding commitment the device signed.
    pub blind: u128,
    /// Device signature on C (Lamport + device-tree path).
    pub sig: DeviceSig<F>,
    /// Position of the device key in the registry and its path.
    pub reg_index: usize,
    pub reg_path: Vec<F>,
    /// Public registry root.
    pub reg_root: F,
}

impl<F: PrimeField + Absorb> UnlinkableCircuit<F> {
    /// The value the device signs for this trace.
    pub fn commitment(&self) -> F {
        commit_native_hiding(&poseidon_config::<F>(), &self.traj, self.blind)
    }

    pub fn public_inputs(&self) -> Vec<F> {
        let mut v = policy_public_inputs(&self.steps, self.avoid.as_ref());
        v.push(self.reg_root);
        v
    }
}

/// Shared part of the unlinkable relations: allocate r, compute the private
/// C = Poseidon(r || T), and enforce that a registered epoch key signed it
/// (Lamport leaf -> epoch root -> registry root `root`). Returns C.
#[allow(clippy::too_many_arguments)]
pub fn enforce_signed_commitment<F: PrimeField + Absorb>(
    cs: &ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    flat: Vec<FpVar<F>>,
    blind: u128,
    sig: &DeviceSig<F>,
    reg_index: usize,
    reg_path: &[F],
    root: &FpVar<F>,
    dev_tag: Option<&FpVar<F>>,
) -> Result<FpVar<F>, SynthesisError> {
    let r = FpVar::new_witness(cs.clone(), || Ok(F::from(blind)))?;
    let mut absorb = vec![r];
    absorb.extend(flat);
    let c = commit_gadget(cs.clone(), cfg, &absorb)?;

    let wit = |v: &[F]| -> Result<Vec<FpVar<F>>, SynthesisError> {
        v.iter().map(|x| FpVar::new_witness(cs.clone(), || Ok(*x))).collect()
    };
    let (reveal, other) = (wit(&sig.ots.reveal)?, wit(&sig.ots.other)?);
    let leaf = ots_pk_hash_gadget(cs.clone(), cfg, &c, &reveal, &other)?;
    let dev_bits = alloc_index_bits(cs.clone(), sig.leaf, sig.path.len())?;
    let epoch_root = merkle_root_gadget(cs.clone(), cfg, leaf, &dev_bits, &wit(&sig.path)?)?;
    let reg_leaf = match dev_tag {
        Some(t) => crate::sig::hash_gadget(cs.clone(), cfg, crate::sig::TAG_REGLEAF, &[epoch_root, t.clone()])?,
        None => epoch_root,
    };
    let reg_bits = alloc_index_bits(cs.clone(), reg_index, reg_path.len())?;
    merkle_root_gadget(cs.clone(), cfg, reg_leaf, &reg_bits, &wit(reg_path)?)?.enforce_equal(root)?;
    Ok(c)
}

impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for UnlinkableCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let cfg = poseidon_config::<F>();
        let pol = alloc_policy(&cs, &self.steps, self.avoid.as_ref())?;
        let root = FpVar::new_input(cs.clone(), || Ok(self.reg_root))?;
        let (xs, ys, ts) = alloc_trajectory(&cs, &self.traj)?;
        let _c = enforce_signed_commitment(&cs, &cfg, flatten_vars(&xs, &ys, &ts), self.blind, &self.sig,
            self.reg_index, &self.reg_path, &root, None)?;
        enforce_policy(&cs, &pol, &xs, &ys, &ts, self.witness.as_deref())
    }
}
