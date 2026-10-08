//! Verifier-side checks (paper, Fig. 1 step 8): statement binding and
//! nullifier replay. Journals come from the guest executor (no proving);
//! the end-to-end test with a real receipt is ignored by default:
//!     cargo test --release -p host --test verifier -- --ignored

use host::{policy_between, setup_fixture, sha, verifier::{Reject, Verifier}};
use methods::ZKMOB_GUEST_ELF;
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};
use zkmob_core::{Journal, Point, Statement, Witness};

const B: u32 = 3;

fn trace() -> Vec<Point> {
    (0..40u32).map(|i| Point { x: 1000 + 50 * i, y: 2000 + 30 * i, t: 10 * i }).collect()
}

fn env(st: &Statement, w: &Witness) -> ExecutorEnv<'static> {
    let bytes = w.to_bytes();
    ExecutorEnv::builder().write(st).unwrap().write_slice(&[bytes.len() as u32]).write_slice(&bytes).build().unwrap()
}

fn journal(st: &Statement, w: &Witness) -> Journal {
    default_executor().execute(env(st, w), ZKMOB_GUEST_ELF).unwrap().journal.decode().unwrap()
}

#[test]
fn accepts_each_slot_once_and_rejects_mismatched_statements() {
    let traj = trace();
    let signed = setup_fixture(traj.clone(), 3, 6, 5);
    let id = sha(&[b"verifier-1"]);
    let policy = policy_between(&traj, 5, 20, 1.5);
    let st = Statement { policy: policy.clone(), reg_root: signed.reg_root, verifier: id, budget: B, period: 7 };
    let mut v = Verifier::new(id, B, signed.reg_root);

    // Every slot is accepted once; a repeat of any slot is a replay.
    for slot in 0..B {
        assert_eq!(v.accept_journal(&journal(&st, &signed.witness(slot)), &policy, 7), Ok(true));
    }
    assert_eq!(v.accept_journal(&journal(&st, &signed.witness(1)), &policy, 7), Err(Reject::Replay));
    assert_eq!(v.accepted(), B as usize);

    // A "no" is accepted like a "yes" and spends its own nullifier.
    let no_policy = policy_between(&traj, 5, 20, 0.5);
    let st_no = Statement { policy: no_policy.clone(), period: 8, ..st.clone() };
    assert_eq!(v.accept_journal(&journal(&st_no, &signed.witness(0)), &no_policy, 8), Ok(false));

    // Statement checks, each on a fresh verifier so no nullifier is spent.
    let fresh = || Verifier::new(id, B, signed.reg_root);
    let j = journal(&st, &signed.witness(0));
    assert_eq!(fresh().accept_journal(&j, &policy, 8), Err(Reject::Period { got: 7, want: 8 }));
    assert_eq!(fresh().accept_journal(&j, &no_policy, 7), Err(Reject::Policy));
    assert_eq!(Verifier::new(sha(&[b"verifier-2"]), B, signed.reg_root).accept_journal(&j, &policy, 7), Err(Reject::Verifier));
    assert_eq!(Verifier::new(id, B, sha(&[b"old root"])).accept_journal(&j, &policy, 7), Err(Reject::Root));

    // A proof made under a larger budget is refused, even for a valid slot.
    let st_big = Statement { budget: B + 1, ..st.clone() };
    let j_big = journal(&st_big, &signed.witness(B));
    assert_eq!(fresh().accept_journal(&j_big, &policy, 7), Err(Reject::Budget { got: B + 1, want: B }));

    // A refused presentation records nothing: the honest one still passes.
    let mut v2 = fresh();
    assert!(v2.accept_journal(&j, &policy, 8).is_err());
    assert_eq!(v2.accepted(), 0);
    assert_eq!(v2.accept_journal(&j, &policy, 7), Ok(true));

    // Slot 0 of period 8 was spent by the "no" above; in a new period the
    // nullifiers are fresh, so the slots renew.
    let st8 = Statement { period: 8, ..st.clone() };
    assert_eq!(v.accept_journal(&journal(&st8, &signed.witness(0)), &policy, 8), Err(Reject::Replay));
    let st9 = Statement { period: 9, ..st.clone() };
    assert_eq!(v.accept_journal(&journal(&st9, &signed.witness(0)), &policy, 9), Ok(true));
}

#[test]
#[ignore = "proves a real receipt (about 25 s)"]
fn real_receipt_is_accepted_once() {
    let traj = trace();
    let signed = setup_fixture(traj.clone(), 3, 6, 5);
    let id = sha(&[b"verifier-1"]);
    let policy = policy_between(&traj, 5, 20, 1.5);
    let st = Statement { policy: policy.clone(), reg_root: signed.reg_root, verifier: id, budget: B, period: 0 };
    let receipt = default_prover().prove_with_opts(env(&st, &signed.witness(0)), ZKMOB_GUEST_ELF, &ProverOpts::succinct()).unwrap().receipt;

    let mut v = Verifier::new(id, B, signed.reg_root);
    assert_eq!(v.accept(&receipt, &policy, 0), Ok(true));
    assert_eq!(v.accept(&receipt, &policy, 0), Err(Reject::Replay));

    // A receipt whose journal was altered no longer verifies.
    let mut forged = receipt.clone();
    let mut j: Journal = forged.journal.decode().unwrap();
    j.outcome = !j.outcome;
    forged.journal = risc0_zkvm::Journal::new(risc0_zkvm::serde::to_vec(&j).unwrap().iter().flat_map(|w| w.to_le_bytes()).collect());
    assert!(matches!(Verifier::new(id, B, signed.reg_root).accept(&forged, &policy, 0), Err(Reject::Receipt(_))));
}
