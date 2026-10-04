//! Small R1CS gadgets written out explicitly so that constraint counts are
//! easy to reason about in the paper (every gadget documents its cost).

use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Decompose `v` into `bits` little-endian bits and enforce the recomposition.
/// Enforces 0 <= v < 2^bits.  Cost: `bits` booleanity + 1 equality.
pub fn enforce_in_range<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    v: &FpVar<F>,
    bits: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let val = v.value().ok();
    let mut out = Vec::with_capacity(bits);
    let mut acc = FpVar::<F>::zero();
    let mut coeff = F::one();
    let big = val.map(|x| x.into_bigint());
    for i in 0..bits {
        let b = Boolean::new_witness(cs.clone(), || {
            let bi = big.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(ark_ff::BigInteger::get_bit(&bi, i))
        })?;
        acc += FpVar::from(b.clone()) * coeff;
        coeff.double_in_place();
        out.push(b);
    }
    acc.enforce_equal(v)?;
    Ok(out)
}

/// Enforce a <= b, assuming both are already known to lie in [0, 2^bits).
/// Cost: bits + 1.
pub fn enforce_leq<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
    b: &FpVar<F>,
    bits: usize,
) -> Result<(), SynthesisError> {
    let d = b - a;
    enforce_in_range(cs, &d, bits)?;
    Ok(())
}

/// Return the bit [a <= b], assuming a, b in [0, 2^bits).
/// d = b - a + 2^bits lies in [1, 2^(bits+1)); its top bit is 1 iff a <= b.
/// Cost: bits + 2.
pub fn is_leq<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
    b: &FpVar<F>,
    bits: usize,
) -> Result<Boolean<F>, SynthesisError> {
    let two_n = F::from(2u64).pow([bits as u64]);
    let d = b - a + FpVar::constant(two_n);
    let dec = enforce_in_range(cs, &d, bits + 1)?;
    Ok(dec[bits].clone())
}

/// Enforce that the point lies inside the box (all bounds public).
/// Cost: 4 * (COORD_BITS + 1).
pub fn enforce_in_box<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    x: &FpVar<F>,
    y: &FpVar<F>,
    b: &[FpVar<F>; 4],
    bits: usize,
) -> Result<(), SynthesisError> {
    enforce_leq(cs.clone(), &b[0], x, bits)?;
    enforce_leq(cs.clone(), x, &b[1], bits)?;
    enforce_leq(cs.clone(), &b[2], y, bits)?;
    enforce_leq(cs, y, &b[3], bits)?;
    Ok(())
}

/// Return the bit [point inside box]. Cost: 4 * (bits + 2) + 3 (ANDs).
pub fn in_box<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    x: &FpVar<F>,
    y: &FpVar<F>,
    b: &[FpVar<F>; 4],
    bits: usize,
) -> Result<Boolean<F>, SynthesisError> {
    let c0 = is_leq(cs.clone(), &b[0], x, bits)?;
    let c1 = is_leq(cs.clone(), x, &b[1], bits)?;
    let c2 = is_leq(cs.clone(), &b[2], y, bits)?;
    let c3 = is_leq(cs, y, &b[3], bits)?;
    Boolean::kary_and(&[c0, c1, c2, c3])
}

/// One-hot selector over n positions with the prover-chosen index `idx`.
/// Returns (selector bits, index as a field element).
/// Cost: n booleanity + 1 (sum == 1). The index is a free linear combination.
pub fn alloc_onehot<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    n: usize,
    idx: Option<usize>,
) -> Result<(Vec<Boolean<F>>, FpVar<F>), SynthesisError> {
    let mut sel = Vec::with_capacity(n);
    let mut sum = FpVar::<F>::zero();
    let mut index = FpVar::<F>::zero();
    for k in 0..n {
        let b = Boolean::new_witness(cs.clone(), || {
            idx.map(|i| i == k).ok_or(SynthesisError::AssignmentMissing)
        })?;
        let bf = FpVar::from(b.clone());
        sum += &bf;
        index += bf * F::from(k as u64);
        sel.push(b);
    }
    sum.enforce_equal(&FpVar::one())?;
    Ok((sel, index))
}

/// Inner product of a one-hot selector with a vector of values.
/// Cost: n multiplications (one per non-constant value).
pub fn select<F: PrimeField>(sel: &[Boolean<F>], vals: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
    let mut acc = FpVar::<F>::zero();
    for (s, v) in sel.iter().zip(vals.iter()) {
        acc += FpVar::from(s.clone()) * v;
    }
    Ok(acc)
}
