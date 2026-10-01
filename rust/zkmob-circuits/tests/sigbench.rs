//! Correctness of the benchmarked one-time signatures (native and in-circuit).

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use zkmob_circuits::sigbench::*;

fn sat(c: SigCircuit<Fr>) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

#[test]
fn all_variants_sign_and_verify() {
    let seed = [4u8; 32];
    let variants = [
        (Scheme::Lamport, false), (Scheme::Wots { log_w: 2 }, false), (Scheme::Wots { log_w: 4 }, false),
        (Scheme::Wots { log_w: 2 }, true),
    ];
    for (scheme, tweaked) in variants {
        for rate in [2usize, 16] {
            let p = Params::<Fr>::new(Variant { scheme, comp_rate: rate, tweaked });
            let pk = p.keygen(&seed, 3);
            // extreme messages exercise all-zero / all-max digits and the checksum
            for m in [Fr::from(0u64), -Fr::from(1u64), Fr::from(0xdead_beef_u64)] {
                let sig = p.sign(&seed, 3, &m);
                assert_eq!(p.verify(&m, &sig), pk, "{:?} native", p.v);
                assert!(sat(SigCircuit { p: &p, m, sig: sig.clone(), pk }), "{:?} circuit", p.v);
                // the same signature must not verify another message
                let m2 = m + Fr::from(1u64);
                assert_ne!(p.verify(&m2, &sig), pk);
                assert!(!sat(SigCircuit { p: &p, m: m2, sig, pk }), "{:?} forged message", p.v);
            }
        }
    }
}

#[test]
fn wots_lengths() {
    assert_eq!(Variant::wots_lens(2, 254), (127, 5));
    assert_eq!(Variant::wots_lens(4, 254), (64, 3));
}
