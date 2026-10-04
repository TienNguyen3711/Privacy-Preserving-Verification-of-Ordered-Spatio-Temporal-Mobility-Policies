//! Device-level budget (review RR-11, 3 Oct 2026): every trace a device signs
//! shares one budget of B answers per verifier.
use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use host::{policy_between, registry::{Device, Manufacturer, Registry}, sha, wallet::Wallet, H};
use zkmob_core::{check, device_tag, Point, Statement};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("zkmob-devbudget-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

fn trip(offset: u32) -> Vec<Point> { (0..8).map(|i| Point { x: 100 * i + offset, y: 100 * i, t: 10 * i }).collect() }

#[test]
fn traces_of_one_device_share_the_budget() {
    let t = Temp::new();
    let mfr = Manufacturer::generate().unwrap();
    let (mut a, ra) = Device::provision(&mfr, 3).unwrap();
    let (mut b, rb) = Device::provision(&mfr, 3).unwrap();
    let reg = Registry::build(mfr.public_key(), 6, vec![ra, rb]).unwrap();
    let (a1, a2, b1) = (a.sign_trace(&reg, trip(0)).unwrap(), a.sign_trace(&reg, trip(7)).unwrap(), b.sign_trace(&reg, trip(0)).unwrap());

    let mut w = Wallet::create(&t.0.join("w"), a1, 3).unwrap();
    assert_eq!(w.add_trace(a2).unwrap(), 1);
    assert!(w.add_trace(b1.clone()).is_err(), "a trace of another device must not join this budget");

    let st = |v: &[u8]| Statement { policy: policy_between(&trip(0), 1, 6, 2.0), reg_root: reg.root, verifier: sha(&[v]), budget: 3, period: 0 };
    let v1 = st(b"verifier-1");
    // Three answers about two different trips use the device's three slots...
    let r0 = w.reserve_for("q0", &v1, 0).unwrap().unwrap();
    let r1 = w.reserve_for("q1", &v1, 1).unwrap().unwrap();
    let r2 = w.reserve_for("q2", &v1, 1).unwrap().unwrap();
    assert_eq!((r0.slot, r1.slot, r2.slot), (0, 1, 2));
    // ...and a fourth, about either trip, is refused.
    assert!(w.reserve_for("q3", &v1, 0).unwrap().is_none());
    assert!(w.reserve_for("q4", &v1, 1).unwrap().is_none());
    // Another verifier has its own budget.
    assert_eq!(w.reserve_for("p0", &st(b"verifier-2"), 1).unwrap().unwrap().slot, 0);

    // The relation accepts both trips under the shared root, and nullifiers
    // depend on (device key, verifier, slot) only: distinct per slot.
    let j0 = check::<H>(&v1, &w.trace(0).unwrap().witness(r0.slot));
    let j1 = check::<H>(&v1, &w.trace(1).unwrap().witness(r1.slot));
    let j2 = check::<H>(&v1, &w.trace(1).unwrap().witness(r2.slot));
    assert!(j0.nullifier != j1.nullifier && j1.nullifier != j2.nullifier);
    // The same slot about another trip of the device gives the same
    // nullifier, so a second answer cannot hide behind a different trip.
    assert_eq!(check::<H>(&v1, &w.trace(1).unwrap().witness(0)).nullifier, j0.nullifier);
    // Another device's nullifiers differ and its leaf carries another tag.
    let jb = check::<H>(&v1, &b1.witness(0));
    assert_ne!(jb.nullifier, j0.nullifier);
    assert_ne!(device_tag::<H>(&b1.dev_key), device_tag::<H>(&w.signed().dev_key));
}

#[test]
fn registry_rejects_a_second_budget_tag_for_one_device() {
    let mfr = Manufacturer::generate().unwrap();
    let (_a, ra) = Device::provision(&mfr, 2).unwrap();
    let mut forged = ra.clone();
    forged.dev_tag[0] ^= 1; // same device key and epoch root, different budget tag
    assert!(Registry::build(mfr.public_key(), 4, vec![ra.clone(), forged]).is_err());
    // the epoch signature covers the tag, so a swapped tag alone is rejected too
    let mut swapped = ra;
    swapped.dev_tag[1] ^= 1;
    assert!(Registry::build(mfr.public_key(), 4, vec![swapped]).is_err());
}

#[test]
fn budget_renews_per_period_only_on_the_wallet_clock() {
    let t = Temp::new();
    let mfr = Manufacturer::generate().unwrap();
    let (mut a, ra) = Device::provision(&mfr, 3).unwrap();
    let reg = Registry::build(mfr.public_key(), 6, vec![ra]).unwrap();
    let mut w = Wallet::create(&t.0.join("w"), a.sign_trace(&reg, trip(0)).unwrap(), 2).unwrap();
    w.set_period_len(2).unwrap();
    let st = |p: u32| Statement { policy: policy_between(&trip(0), 1, 6, 2.0), reg_root: reg.root, verifier: sha(&[b"v"]), budget: 2, period: p };
    // start at the beginning of a period so the test does not straddle one
    let p0 = w.current_period().unwrap();
    while w.current_period().unwrap() == p0 { std::thread::sleep(std::time::Duration::from_millis(20)); }
    let p = w.current_period().unwrap();
    let r0 = w.reserve("a", &st(p)).unwrap().unwrap();
    assert_eq!(w.reserve("b", &st(p)).unwrap().unwrap().slot, 1);
    assert!(w.reserve("c", &st(p)).unwrap().is_none(), "B per period");
    // the verifier cannot name a future period to get fresh slots
    assert!(w.reserve("d", &st(p + 1)).is_err());
    assert!(w.set_period_len(1).is_err(), "period length fixed after the first request");
    while w.current_period().unwrap() == p { std::thread::sleep(std::time::Duration::from_millis(20)); }
    let r1 = w.reserve("e", &st(p + 1)).unwrap().unwrap();
    assert_eq!(r1.slot, 0, "fresh budget in the next period");
    // a retry from the old period still returns its own reservation
    assert_eq!(w.reserve("a", &st(p)).unwrap().unwrap().slot, r0.slot);
    // same slot, next period: a different nullifier
    let j0 = check::<H>(&st(p), &w.signed().witness(r0.slot));
    let j1 = check::<H>(&st(p + 1), &w.signed().witness(r1.slot));
    assert_ne!(j0.nullifier, j1.nullifier);
}
