use std::{path::PathBuf, process::{Command, Stdio}, time::{SystemTime, UNIX_EPOCH}};
use host::{setup_fixture, setup_randomized_local, policy_between, sha, wallet::Wallet};
use zkmob_core::{check, Point, Statement};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        // Counter avoids name collisions between tests started in the same clock tick.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let k = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("zkmob-wallet-{}-{}-{k}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&p).unwrap(); Self(p)
    }
    fn wallet(&self) -> PathBuf { self.0.join("wallet") }
}
impl Drop for Temp { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn trace() -> Vec<Point> { (0..8).map(|i| Point { x: i*100, y: i*100, t: i*10 }).collect() }
fn create(t: &Temp, b: u32) -> Wallet {
    Wallet::create(&t.wallet(), setup_randomized_local(trace(), 2, 4, 2).unwrap(), b).unwrap()
}
fn statement(w: &Wallet) -> Statement {
    Statement { policy: policy_between(&w.signed().traj, 1, 6, 2.0),
        reg_root: w.signed().reg_root, verifier: sha(&[b"authenticated-test-verifier"]), budget: w.budget(), period: 0 }
}

#[test]
fn restart_keeps_commitment_cap_pending_and_cached_response() {
    let t = Temp::new();
    let mut w = create(&t, 2);
    let st = statement(&w);
    let blind = w.signed().blind;
    assert_eq!(w.reserve("a", &st).unwrap().unwrap().slot, 0);
    drop(w); // simulates stop after durable reservation, before proving
    let mut w = Wallet::open(&t.wallet()).unwrap();
    assert_eq!(w.signed().blind, blind);
    assert_eq!(w.reserve("a", &st).unwrap().unwrap().slot, 0);
    // Storage layer holds opaque responses; actual prover verifies receipts.
    w.complete("a", &st, b"opaque-response".to_vec()).unwrap();
    drop(w);
    let mut w = Wallet::open(&t.wallet()).unwrap();
    assert_eq!(w.reserve("a", &st).unwrap().unwrap().response.unwrap(), b"opaque-response");
    assert_eq!(w.reserve("b", &st).unwrap().unwrap().slot, 1);
    assert!(w.reserve("c", &st).unwrap().is_none());
    assert!(w.reserve("a", &st).unwrap().unwrap().response.is_some());
    assert!(w.complete("a", &st, b"changed".to_vec()).is_err());
}

#[test]
fn immutable_context_and_no_refund_for_either_outcome() {
    let t = Temp::new(); let mut w = create(&t, 2); let yes = statement(&w);
    let mut no = yes.clone(); no.policy.steps[1].zone.xmin = 9000; no.policy.steps[1].zone.xmax = 9100;
    assert!(check::<host::H>(&yes, &w.signed().witness(0)).outcome);
    assert!(!check::<host::H>(&no, &w.signed().witness(1)).outcome);
    w.reserve("yes", &yes).unwrap();
    assert!(w.reserve("yes", &no).is_err());
    w.reserve("no", &no).unwrap();
    assert!(w.reserve("extra", &yes).unwrap().is_none());
    let mut higher = yes.clone(); higher.budget = 3;
    assert!(w.reserve("extra", &higher).is_err());
    higher = yes.clone(); higher.reg_root[0] ^= 1;
    assert!(w.reserve("extra", &higher).is_err());
    let mut other = yes.clone(); other.verifier[0] ^= 1;
    assert_eq!(w.reserve("yes", &other).unwrap().unwrap().slot, 0);
}

#[test]
fn subprocess_worker() {
    let Some(path) = std::env::var_os("ZKMOB_TEST_WALLET") else { return; };
    let mut w = Wallet::open(&PathBuf::from(path)).unwrap();
    let st = statement(&w);
    let id = std::env::var("ZKMOB_TEST_REQUEST").unwrap();
    let reserved = w.reserve(&id, &st).unwrap().is_some();
    // No destructors run: lock release and reservation durability must survive.
    std::process::exit(if reserved { 10 } else { 11 });
}

#[test]
fn simultaneous_processes_and_abrupt_exit_do_not_overspend() {
    let t = Temp::new(); drop(create(&t, 3));
    let mut children: Vec<_> = (0..12).map(|i| Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "subprocess_worker"])
        .env("ZKMOB_TEST_WALLET", t.wallet()).env("ZKMOB_TEST_REQUEST", format!("r{i}"))
        .stdout(Stdio::null()).spawn().unwrap()).collect();
    let codes: Vec<_> = children.iter_mut().map(|c| c.wait().unwrap().code().unwrap()).collect();
    assert_eq!(codes.iter().filter(|&&c| c == 10).count(), 3);
    assert_eq!(codes.iter().filter(|&&c| c == 11).count(), 9);
    let mut w = Wallet::open(&t.wallet()).unwrap();
    let st = statement(&w);
    assert!(w.reserve("later", &st).unwrap().is_none());
}

#[test]
fn missing_corrupt_state_and_reinitialisation_fail_closed() {
    let t = Temp::new(); drop(create(&t, 1));
    assert!(Wallet::create(&t.wallet(), setup_fixture(trace(), 2, 4, 2), 99).is_err());
    std::fs::write(t.wallet().join("state.json"), "broken").unwrap();
    assert!(Wallet::open(&t.wallet()).is_err());
    std::fs::remove_file(t.wallet().join("state.json")).unwrap();
    assert!(Wallet::open(&t.wallet()).is_err());
}

#[test]
fn storage_error_poisoning_prevents_unpersisted_release() {
    let t = Temp::new(); let mut w = create(&t, 1); let st = statement(&w);
    std::fs::create_dir(t.wallet().join("state.pending")).unwrap();
    assert!(w.reserve("a", &st).is_err());
    assert!(w.reserve("a", &st).is_err());
    assert!(w.complete("a", &st, vec![1]).is_err());
    drop(w);
    std::fs::remove_dir(t.wallet().join("state.pending")).unwrap();
    let mut w = Wallet::open(&t.wallet()).unwrap();
    assert_eq!(w.reserve("a", &st).unwrap().unwrap().slot, 0);
}

#[test]
fn private_permissions_and_fresh_entropy() {
    use std::os::unix::fs::PermissionsExt;
    let t = Temp::new(); let w = create(&t, 0);
    assert_eq!(std::fs::metadata(t.wallet()).unwrap().permissions().mode() & 0o777, 0o700);
    for f in ["state.json", "wallet.lock"] {
        assert_eq!(std::fs::metadata(t.wallet().join(f)).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let other = setup_randomized_local(trace(), 2, 4, 2).unwrap();
    assert_ne!(w.signed().blind, other.blind);
    assert_ne!(w.signed().reg_root, other.reg_root);
    let a = setup_fixture(trace(), 2, 4, 2); let b = setup_fixture(trace(), 2, 4, 2);
    assert_eq!(a.blind, b.blind);
    assert_eq!(a.reg_root, b.reg_root);
}

#[test]
fn blind_is_256_bits_and_latency_is_persisted() {
    let t = Temp::new();
    let w = Wallet::create_with_latency(&t.wallet(), setup_randomized_local(trace(), 2, 4, 2).unwrap(), 2, 45_000).unwrap();
    assert_eq!(w.signed().blind.len(), 32);
    assert_eq!(w.release_latency_ms(), 45_000);
    drop(w);
    let w = Wallet::open(&t.wallet()).unwrap();
    assert_eq!(w.release_latency_ms(), 45_000, "latency survives restart unchanged");
}

#[test]
fn expired_request_burns_slot_and_never_releases() {
    let t = Temp::new();
    let mut w = create(&t, 2);
    let st = statement(&w);
    assert_eq!(w.reserve("late", &st).unwrap().unwrap().slot, 0);
    w.expire("late", &st).unwrap();
    w.expire("late", &st).unwrap(); // idempotent
    drop(w);
    let mut w = Wallet::open(&t.wallet()).unwrap();
    let r = w.reserve("late", &st).unwrap().unwrap();
    assert!(r.expired && r.response.is_none(), "request stays expired");
    assert!(w.complete("late", &st, b"again".to_vec()).is_err(), "expired request cannot complete");
    assert_eq!(w.reserve("next", &st).unwrap().unwrap().slot, 1, "expired slot is not refunded");
    assert!(w.reserve("third", &st).unwrap().is_none(), "budget still bounded");
    w.complete("next", &st, b"answer".to_vec()).unwrap();
    assert!(w.expire("next", &st).is_err(), "a completed response may have been released; it cannot expire");
}

/// Review R1: the deadline is fixed durably at reservation, survives a crash
/// and resumption, and no response can be stored before it, so a retry after
/// a crash can never release a response early.
#[test]
fn release_deadline_is_durable_and_completion_waits_for_it() {
    let t = Temp::new();
    let mut w = Wallet::create_with_latency(&t.wallet(), setup_randomized_local(trace(), 2, 4, 2).unwrap(), 2, 60_000).unwrap();
    let st = statement(&w);
    let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let r = w.reserve("q", &st).unwrap().unwrap();
    assert!(r.deadline_ms >= before + 60_000 && r.deadline_ms <= before + 61_000);
    assert!(w.complete("q", &st, b"early".to_vec()).is_err(), "completion before the deadline is refused");
    drop(w); // crash/restart while the request is pending
    let mut w = Wallet::open(&t.wallet()).unwrap();
    let again = w.reserve("q", &st).unwrap().unwrap();
    assert_eq!(again.deadline_ms, r.deadline_ms, "resumed request keeps its original deadline");
    assert!(again.response.is_none());
    assert!(w.complete("q", &st, b"early".to_vec()).is_err());
}

/// Review R5: a policy outside the supported domain is rejected by public
/// admission before any slot is reserved.
#[test]
fn unsupported_policy_is_rejected_before_reservation() {
    let t = Temp::new();
    let traces = t.0.join("traces.jsonl");
    let pts: Vec<[u32; 3]> = trace().iter().map(|p| [p.x, p.y, p.t]).collect();
    std::fs::write(&traces, format!("{{\"points\": {}}}\n", serde_json::to_string(&pts).unwrap())).unwrap();
    let bin = env!("CARGO_BIN_EXE_wallet_prove");
    let init = Command::new(bin).args(["--legacy-plaintext", "--init", "--wallet"]).arg(t.wallet())
        .args(["--traces"]).arg(&traces).args(["--n", "8", "--budget", "2", "--latency-ms", "0", "--local-registry"]).output().unwrap();
    assert!(init.status.success(), "{}", String::from_utf8_lossy(&init.stderr));
    let zone = r#"{"zone":{"xmin":0,"xmax":4294967295,"ymin":0,"ymax":4294967295},"max_gap":null}"#;
    let policy = t.0.join("nine.json");
    std::fs::write(&policy, format!(r#"{{"steps":[{}],"avoid":null}}"#, vec![zone; 9].join(","))).unwrap();
    let out = Command::new(bin).args(["--legacy-plaintext", "--wallet"]).arg(t.wallet()).arg("--policy").arg(&policy)
        .args(["--request-id", "nine", "--verifier", &"01".repeat(32)]).output().unwrap();
    assert!(!out.status.success() && out.stdout.is_empty());
    assert_eq!(out.status.code(), Some(1), "a clean admission error, not a panic");
    let state = std::fs::read_to_string(t.wallet().join("state.json")).unwrap();
    assert!(!state.contains("\"nine\""), "no slot was reserved");
}

#[test]
fn older_wallet_versions_are_rejected() {
    let t = Temp::new();
    drop(create(&t, 2));
    let path = t.wallet().join("state.json");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"version\":6"));
    std::fs::write(&path, text.replacen("\"version\":6", "\"version\":5", 1)).unwrap();
    let err = Wallet::open(&t.wallet()).err().expect("older wallets must be rejected");
    assert!(err.to_string().contains("unsupported wallet version"));
}

/// Regression (1 Oct 2026): receipts used to be JSON arrays inside the state,
/// so every request re-read and re-wrote all stored receipts (4.2 s per
/// cached retry after 17 receipts). v4 stores them as separate files.
#[test]
fn request_cost_does_not_grow_with_stored_receipts() {
    let t = Temp::new();
    let mut w = Wallet::create(&t.wallet(), setup_randomized_local(trace(), 2, 4, 2).unwrap(), 50).unwrap();
    let st = statement(&w);
    let receipt = vec![0xA5u8; 224_066];
    for i in 0..50 {
        let id = format!("r{i}");
        w.reserve(&id, &st).unwrap().unwrap();
        let mut r = receipt.clone();
        r[..4].copy_from_slice(&(i as u32).to_le_bytes());
        w.complete(&id, &st, r).unwrap();
    }
    drop(w);
    let state_bytes = std::fs::metadata(t.wallet().join("state.json")).unwrap().len();
    assert!(state_bytes < 100_000, "state holds receipts inline: {state_bytes} bytes");
    let start = std::time::Instant::now();
    let mut w = Wallet::open(&t.wallet()).unwrap();
    let r = w.reserve("r49", &st).unwrap().unwrap().response.unwrap();
    assert_eq!(&r[..4], &49u32.to_le_bytes());
    assert!(start.elapsed().as_millis() < 500, "open + cached retry took {:?}", start.elapsed());
    // A stored receipt that was altered on disk is never released.
    let dir = t.wallet().join("receipts");
    let any = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
    let mut bytes = std::fs::read(&any).unwrap();
    bytes[100] ^= 1;
    std::fs::write(&any, bytes).unwrap();
    let mut failed = 0;
    for i in 0..50 { if w.reserve(&format!("r{i}"), &st).is_err() { failed += 1; } }
    assert_eq!(failed, 1, "exactly the altered receipt fails closed");
}
