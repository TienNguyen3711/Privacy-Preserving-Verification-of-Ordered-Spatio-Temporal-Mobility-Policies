//! Hidden-signature microbenchmark: which one-time signature is cheapest to
//! verify INSIDE the proof?
//!
//! Variants (all sign the 254-bit commitment C, secrets derived with the same
//! SHA-512 PRF as `sig.rs`, chain/leaf hash = Poseidon t = 3):
//! * Lamport          2 x 254 preimages; reveal one per message bit
//! * WOTS, w = 4      132 chains of length 3 (127 message + 5 checksum digits)
//! * WOTS, w = 16     67 chains of length 15 (64 message + 3 checksum digits)
//! each with the public key (the list of chain ends) compressed by a Poseidon
//! sponge of rate 2 (t = 3, current), 8 (t = 9) or 16 (t = 17).
//!
//! In-circuit, a WOTS chain has to compute ALL w - 1 steps and select, because
//! the digit is private; the circuit cost is the worst case, not the average.
//! WOTS chains come untweaked (H(tag, x), like the Lamport leaf hashes) or
//! tweaked (`wots_w4x`: H(tag, chain, step, x) with a t = 5 sponge), which is
//! the address-bound form WOTS+ (RFC 8391) needs for its standard security
//! proof. Lamport needs only a one-way function, so it has no tweak.
//!
//! Poseidon partial rounds for BN254, alpha = 5, 128-bit security, as in the
//! Poseidon paper / circomlib: t = 3: 57, t = 5: 60, t = 9: 63, t = 17: 68.

use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{enforce_in_range, is_leq};
use crate::sig::{hash_gadget, msg_bits, ots_secret, TAG_OTS, TAG_PK};

/// Poseidon over the scalar field with the given rate (capacity 1).
pub fn poseidon_config_rate<F: PrimeField>(rate: usize) -> PoseidonConfig<F> {
    let partial = match rate {
        2 => 57,
        4 => 60,
        8 => 63,
        16 => 68,
        _ => panic!("no parameters for rate {rate}"),
    };
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, rate, 8, partial, 0);
    PoseidonConfig::new(8, partial as usize, 5, mds, ark, rate, 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Lamport,
    Wots { log_w: usize },
}

#[derive(Clone, Copy, Debug)]
pub struct Variant {
    pub scheme: Scheme,
    /// Rate of the sponge that compresses the public key.
    pub comp_rate: usize,
    /// WOTS only: address-bound chain hashes (WOTS+ style).
    pub tweaked: bool,
}

impl Variant {
    pub fn name(&self) -> String {
        let s = match self.scheme {
            Scheme::Lamport => "lamport".to_string(),
            Scheme::Wots { log_w } => format!("wots_w{}{}", 1 << log_w, if self.tweaked { "x" } else { "" }),
        };
        format!("{s}_t{}", self.comp_rate + 1)
    }

    /// (message digits, checksum digits) for WOTS over `nbits` bits.
    pub fn wots_lens(log_w: usize, nbits: usize) -> (usize, usize) {
        let w = 1usize << log_w;
        let l1 = nbits.div_ceil(log_w);
        let max_csum = l1 * (w - 1);
        let cbits = (usize::BITS - max_csum.leading_zeros()) as usize;
        (l1, cbits.div_ceil(log_w))
    }

    /// Number of field elements in a signature.
    pub fn sig_len(&self, nbits: usize) -> usize {
        match self.scheme {
            Scheme::Lamport => 2 * nbits,
            Scheme::Wots { log_w } => {
                let (l1, l2) = Self::wots_lens(log_w, nbits);
                l1 + l2
            }
        }
    }
}

fn sponge<F: PrimeField + Absorb>(cfg: &PoseidonConfig<F>, tag: u64, xs: &[F]) -> F {
    let mut v = vec![F::from(tag)];
    v.extend_from_slice(xs);
    let mut s = PoseidonSponge::<F>::new(cfg);
    s.absorb(&v);
    s.squeeze_field_elements::<F>(1)[0]
}

fn sponge_gadget<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    tag: u64,
    xs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut v = vec![FpVar::constant(F::from(tag))];
    v.extend_from_slice(xs);
    let mut s = PoseidonSpongeVar::<F>::new(cs, cfg);
    s.absorb(&v)?;
    Ok(s.squeeze_field_elements(1)?.remove(0))
}

/// Parameters for one variant.
pub struct Params<F: PrimeField> {
    pub v: Variant,
    pub narrow: PoseidonConfig<F>,
    pub comp: PoseidonConfig<F>,
    pub tweak: PoseidonConfig<F>,
    pub nbits: usize,
}

pub const TAG_CHAIN: u64 = 0xc4a1;

impl<F: PrimeField + Absorb> Params<F> {
    pub fn new(v: Variant) -> Self {
        Params {
            v,
            narrow: poseidon_config_rate(2),
            comp: poseidon_config_rate(v.comp_rate),
            tweak: poseidon_config_rate(4),
            nbits: F::MODULUS_BIT_SIZE as usize,
        }
    }

    fn h(&self, x: F) -> F {
        sponge(&self.narrow, TAG_OTS, &[x])
    }

    /// One chain step at absolute position `step` of chain `chain`.
    fn step(&self, chain: usize, step: usize, x: F) -> F {
        if self.v.tweaked {
            sponge(&self.tweak, TAG_CHAIN, &[F::from(chain as u64), F::from(step as u64), x])
        } else {
            self.h(x)
        }
    }

    /// Apply steps `from .. to` of chain `chain`.
    fn chain(&self, chain: usize, mut x: F, from: usize, to: usize) -> F {
        for k in from..to {
            x = self.step(chain, k, x);
        }
        x
    }

    /// Base-w digits of m followed by the checksum digits (little-endian).
    pub fn digits(&self, m: &F) -> Vec<usize> {
        let Scheme::Wots { log_w } = self.v.scheme else { unreachable!() };
        let w = 1usize << log_w;
        let bits = msg_bits(m);
        let (l1, l2) = Variant::wots_lens(log_w, self.nbits);
        let mut d: Vec<usize> = (0..l1)
            .map(|i| (0..log_w).map(|k| (*bits.get(i * log_w + k).unwrap_or(&false) as usize) << k).sum())
            .collect();
        let mut csum: usize = d.iter().map(|x| w - 1 - x).sum();
        for _ in 0..l2 {
            d.push(csum & (w - 1));
            csum >>= log_w;
        }
        d
    }

    fn secrets(&self, seed: &[u8; 32], leaf: u64) -> Vec<F> {
        (0..self.v.sig_len(self.nbits) as u64).map(|i| ots_secret(seed, leaf, i)).collect()
    }

    /// Public-key hash of one-time key `leaf`.
    pub fn keygen(&self, seed: &[u8; 32], leaf: u64) -> F {
        let sk = self.secrets(seed, leaf);
        let pk: Vec<F> = match self.v.scheme {
            Scheme::Lamport => sk.iter().map(|s| self.h(*s)).collect(),
            Scheme::Wots { log_w } => sk.iter().enumerate().map(|(i, s)| self.chain(i, *s, 0, (1 << log_w) - 1)).collect(),
        };
        sponge(&self.comp, TAG_PK, &pk)
    }

    pub fn sign(&self, seed: &[u8; 32], leaf: u64, m: &F) -> Vec<F> {
        let sk = self.secrets(seed, leaf);
        match self.v.scheme {
            // layout: [reveal_0, other_0, reveal_1, other_1, ...]
            Scheme::Lamport => msg_bits(m)
                .iter()
                .enumerate()
                .flat_map(|(i, &b)| {
                    let (s0, s1) = (sk[2 * i], sk[2 * i + 1]);
                    if b { [s1, self.h(s0)] } else { [s0, self.h(s1)] }
                })
                .collect(),
            Scheme::Wots { .. } => self.digits(m).iter().zip(&sk).enumerate().map(|(i, (d, s))| self.chain(i, *s, 0, *d)).collect(),
        }
    }

    /// Recompute the public-key hash from (m, sig).
    pub fn verify(&self, m: &F, sig: &[F]) -> F {
        let pk: Vec<F> = match self.v.scheme {
            Scheme::Lamport => msg_bits(m)
                .iter()
                .enumerate()
                .flat_map(|(i, &b)| {
                    let (rev, oth) = (self.h(sig[2 * i]), sig[2 * i + 1]);
                    if b { [oth, rev] } else { [rev, oth] }
                })
                .collect(),
            Scheme::Wots { log_w } => {
                let w = 1usize << log_w;
                self.digits(m).iter().zip(sig).enumerate().map(|(i, (d, s))| self.chain(i, *s, *d, w - 1)).collect()
            }
        };
        sponge(&self.comp, TAG_PK, &pk)
    }

    /// In-circuit verification; returns the public-key hash.
    pub fn verify_gadget(
        &self,
        cs: ConstraintSystemRef<F>,
        m: &FpVar<F>,
        sig: &[FpVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        let bits = m.to_bits_le()?;
        let pk: Vec<FpVar<F>> = match self.v.scheme {
            Scheme::Lamport => {
                let mut pk = Vec::with_capacity(2 * self.nbits);
                for i in 0..self.nbits {
                    let hv = hash_gadget(cs.clone(), &self.narrow, TAG_OTS, &[sig[2 * i].clone()])?;
                    let oth = &sig[2 * i + 1];
                    pk.push(FpVar::conditionally_select(&bits[i], oth, &hv)?);
                    pk.push(FpVar::conditionally_select(&bits[i], &hv, oth)?);
                }
                pk
            }
            Scheme::Wots { log_w } => {
                let w = 1usize << log_w;
                let (l1, l2) = Variant::wots_lens(log_w, self.nbits);
                let digit = |chunk: &[Boolean<F>]| -> FpVar<F> {
                    chunk.iter().enumerate().fold(FpVar::zero(), |acc, (k, b)| acc + FpVar::from(b.clone()) * F::from(1u64 << k))
                };
                let mut digits: Vec<FpVar<F>> = (0..l1)
                    .map(|i| {
                        let hi = ((i + 1) * log_w).min(self.nbits);
                        digit(&bits[i * log_w..hi])
                    })
                    .collect();
                let csum = digits.iter().fold(FpVar::zero(), |acc, d| acc + (FpVar::constant(F::from((w - 1) as u64)) - d));
                let cbits = enforce_in_range(cs.clone(), &csum, l2 * log_w)?;
                for j in 0..l2 {
                    digits.push(digit(&cbits[j * log_w..(j + 1) * log_w]));
                }
                let mut pk = Vec::with_capacity(l1 + l2);
                for (i, (d, s)) in digits.iter().zip(sig).enumerate() {
                    let mut cur = s.clone();
                    for k in 0..w - 1 {
                        // apply step k iff d <= k  (w - 1 - d steps in total)
                        let apply = is_leq(cs.clone(), d, &FpVar::constant(F::from(k as u64)), log_w)?;
                        let nxt = if self.v.tweaked {
                            let (ci, ki) = (FpVar::constant(F::from(i as u64)), FpVar::constant(F::from(k as u64)));
                            sponge_gadget(cs.clone(), &self.tweak, TAG_CHAIN, &[ci, ki, cur.clone()])?
                        } else {
                            hash_gadget(cs.clone(), &self.narrow, TAG_OTS, &[cur.clone()])?
                        };
                        cur = FpVar::conditionally_select(&apply, &nxt, &cur)?;
                    }
                    pk.push(cur);
                }
                pk
            }
        };
        sponge_gadget(cs, &self.comp, TAG_PK, &pk)
    }
}

/// Stand-alone circuit: public pk hash; witness message and signature.
pub struct SigCircuit<'a, F: PrimeField> {
    pub p: &'a Params<F>,
    pub m: F,
    pub sig: Vec<F>,
    pub pk: F,
}

impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for SigCircuit<'_, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pk = FpVar::new_input(cs.clone(), || Ok(self.pk))?;
        let m = FpVar::new_witness(cs.clone(), || Ok(self.m))?;
        let sig: Vec<FpVar<F>> = self.sig.iter().map(|s| FpVar::new_witness(cs.clone(), || Ok(*s))).collect::<Result<_, _>>()?;
        self.p.verify_gadget(cs, &m, &sig)?.enforce_equal(&pk)
    }
}
