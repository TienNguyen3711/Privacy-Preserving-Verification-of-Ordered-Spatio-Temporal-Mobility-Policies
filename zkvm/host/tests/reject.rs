//! The guest must refuse invalid witnesses (executor only; no proving).

use host::*;
use methods::ZKMOB_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use zkmob_core::{check, Journal, Point, Statement};

fn run(st: &Statement, w: &zkmob_core::Witness) -> Result<Journal, String> {
    let env = ExecutorEnv::builder().write(st).unwrap().write_slice(&[w.to_bytes().len() as u32]).write_slice(&w.to_bytes()).build().unwrap();
    default_executor().execute(env, ZKMOB_GUEST_ELF).map_err(|e| e.to_string()).map(|s| s.journal.decode().unwrap())
}

fn trace() -> Vec<Point> {
    (0..40u32).map(|i| Point { x: 1000 + 50 * i, y: 2000 + 30 * i, t: 10 * i }).collect()
}

#[test]
fn guest_accepts_honest_and_rejects_forgeries() {
    let traj = trace();
    let signed = setup_fixture(traj.clone(), 3, 6, 5);
    let v = sha(&[b"v"]);
    let yes = Statement { policy: policy_between(&traj, 5, 20, 1.5), reg_root: signed.reg_root, verifier: v, budget: 3, period: 0 };
    let no = Statement { policy: policy_between(&traj, 5, 20, 0.5), ..yes.clone() };

    // honest: both outcomes, journal equals the native relation
    for st in [&yes, &no] {
        let w = signed.witness(0);
        assert_eq!(run(st, &w).unwrap(), check::<H>(st, &w));
    }
    assert!(run(&yes, &signed.witness(0)).unwrap().outcome);
    assert!(!run(&no, &signed.witness(0)).unwrap().outcome);

    // forged trace (device never signed it)
    let mut w = signed.witness(0);
    w.traj[3].x += 1;
    assert!(run(&yes, &w).is_err(), "tampered trace");
    // wrong blinding value
    let mut w = signed.witness(0);
    w.blind[0] ^= 1;
    assert!(run(&yes, &w).is_err(), "wrong blinding");
    // slot outside the budget
    assert!(run(&yes, &signed.witness(3)).is_err(), "slot = budget");
    // different registry root (e.g. unregistered epoch)
    let mut st = yes.clone();
    st.reg_root[0] ^= 1;
    assert!(run(&st, &signed.witness(0)).is_err(), "wrong registry");
    // unsorted trace
    let mut w = signed.witness(0);
    w.traj.swap(1, 2);
    assert!(run(&yes, &w).is_err(), "unsorted (and unsigned) trace");
    // nullifiers differ across slots
    assert_ne!(run(&yes, &signed.witness(0)).unwrap().nullifier, run(&yes, &signed.witness(1)).unwrap().nullifier);
}
