//! zkmob-circuits: R1CS circuits for zero-knowledge verification of ordered,
//! spatio-temporal mobility policies (Paper 3 pilot).
//!
//! * `ordered`   – our selector-based design (claim N1)
//! * `automaton` – baseline B3: discretise + DFA (Reef / zkreg style)
//! * `commit`    – Poseidon commitment (binding B2, or hiding) to a signed trace
//! * `io`        – JSON bridge from the Python data pipeline
//!
//! The pilot uses Groth16 over BN254 because it gives exact constraint counts
//! and fast iteration. BN254 is NOT post-quantum: the PQ back end (a STARK
//! with zero-knowledge trace masking) is a later milestone, see README.

pub mod automaton;
pub mod budget;
pub mod commit;
pub mod gadgets;
pub mod io;
pub mod ordered;
pub mod scenario;
pub mod sig;
pub mod sigbench;
pub mod unlinkable;
pub mod types;

pub mod synth {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};

    /// Synthesize a circuit and return (num_constraints, satisfied).
    pub fn count<F: ark_ff::PrimeField, C: ConstraintSynthesizer<F>>(c: C) -> (usize, bool) {
        let cs = ConstraintSystem::<F>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        c.generate_constraints(cs.clone()).expect("synthesis");
        cs.finalize();
        (cs.num_constraints(), cs.is_satisfied().unwrap_or(false))
    }
}
