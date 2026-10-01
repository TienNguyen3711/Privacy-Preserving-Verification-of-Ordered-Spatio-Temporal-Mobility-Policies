//! Simulated power loss (crash-state enumeration) for the protected wallet.
//!
//! Not a physical power cut. The wallet's write protocol is: write
//! state.pending, fsync it, fsync the directory, compare-and-swap the ledger
//! head, rename to state.enc, fsync the directory. After a power cut, data or
//! names not yet fsynced may be lost or torn; fsynced data survives (Rust's
//! `sync_all` uses F_FULLFSYNC on macOS). For every crash point we build each
//! disk state the cut can leave, pair it with the ledger state at that point
//! (the ledger is a separate host and is not affected), reopen the wallet
//! against the real ledger process, and check:
//!   * safety: the wallet opens only the state the ledger has committed, so a
//!     committed reservation is never refunded and no rollback is accepted;
//!   * liveness: which states recover without manual intervention.
use std::{fs, io::{BufRead, BufReader}, path::{Path, PathBuf}, process::{Child, Command, Stdio}, time::{SystemTime, UNIX_EPOCH}};
use host::{anchor::Anchor, vault, wallet::Wallet, setup_randomized_local, policy_between, sha};
use zkmob_core::{Point, Statement};

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const KEY: [u8; 32] = [7; 32];

struct Service { root: PathBuf, child: Child, url: String, token: [u8; 32] }
impl Service {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("zkmob-power-{}-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../python/zkmob/anchor_service.py");
        vault::generate_key(&root.join("token")).unwrap();
        let token = *vault::load_key(&root.join("token")).unwrap();
        assert!(Command::new("python3").arg(&script).args(["--init", "--state-dir"]).arg(root.join("ledger")).status().unwrap().success());
        let mut child = Command::new("python3").arg(script).arg("--state-dir").arg(root.join("ledger"))
            .arg("--token-file").arg(root.join("token")).args(["--port", "0"]).stdout(Stdio::piped()).spawn().unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port = serde_json::from_str::<serde_json::Value>(&line).unwrap()["port"].as_u64().unwrap();
        Self { root, child, url: format!("http://127.0.0.1:{port}"), token }
    }
    fn client(&self) -> Anchor { Anchor::new(&self.url, &self.token, true).unwrap() }
}
impl Drop for Service { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = fs::remove_dir_all(&self.root); } }

fn statement(w: &Wallet) -> Statement {
    Statement { policy: policy_between(&w.signed().traj, 1, 6, 2.), reg_root: w.signed().reg_root, verifier: sha(&[b"v"]), budget: w.budget() }
}

/// A complete next snapshot that was never committed: S0 with the next revision.
fn uncommitted_next(s0: &[u8]) -> Vec<u8> {
    let mut state: serde_json::Value = serde_json::from_slice(&vault::open(&KEY, s0).unwrap()).unwrap();
    let rev = state["anchor"]["revision"].as_u64().unwrap();
    state["anchor"]["revision"] = (rev + 1).into();
    vault::seal(&KEY, &serde_json::to_vec(&state).unwrap()).unwrap()
}

#[derive(Debug, PartialEq)]
enum Outcome { Recovered { spent: u32 }, FailClosed }

/// Open after the cut (read-only) and report the slots the wallet counts as spent.
fn reopen(s: &Service, dir: &Path, st: &Statement) -> Outcome {
    match Wallet::open_protected(dir, KEY, s.client()) {
        Err(_) => Outcome::FailClosed,
        Ok(w) => Outcome::Recovered { spent: w.spent(st) },
    }
}

fn traj() -> Vec<Point> { (0..8).map(|i| Point { x: 100 * i, y: 100 * i, t: 10 * i }).collect() }

/// Fresh ledger and wallet: returns (service, dir, statement, S0 bytes).
fn world() -> (Service, PathBuf, Statement, Vec<u8>) {
    let s = Service::new();
    let dir = s.root.join("w");
    let w = Wallet::create_protected(&dir, setup_randomized_local(traj(), 2, 4, 2).unwrap(), 2, KEY, s.client()).unwrap();
    let st = statement(&w);
    drop(w);
    let s0 = fs::read(dir.join("state.enc")).unwrap();
    (s, dir, st, s0)
}

#[test]
fn power_loss_crash_states_never_refund_or_roll_back() {
    let mut report = Vec::new();
    // Cut before the ledger CAS: the ledger still holds S0 (nothing spent).
    // Disk: state.enc = S0 (fsynced earlier); state.pending as the cut leaves it.
    // cut(len) = bytes of the next snapshot that reached the disk (None: file absent)
    let variants: Vec<(&str, fn(usize) -> Option<usize>)> = vec![
        ("pending absent", |_| None),
        ("pending empty", |_| Some(0)),
        ("pending torn at 1 byte", |_| Some(1)),
        ("pending torn at 16 bytes", |_| Some(16)),
        ("pending torn at half", |n| Some(n / 2)),
        ("pending torn at len-1", |n| Some(n - 1)),
        ("pending complete, uncommitted", |n| Some(n)),
    ];
    for (name, cut) in variants {
        let (s, dir, st, s0) = world();
        let next = uncommitted_next(&s0);
        if let Some(k) = cut(next.len()) { fs::write(dir.join("state.pending"), &next[..k]).unwrap(); }
        let out = reopen(&s, &dir, &st);
        // Ledger holds S0: the wallet must recover with nothing spent (an
        // uncommitted pending file, torn or complete, is discarded).
        assert_eq!(out, Outcome::Recovered { spent: 0 }, "{name}");
        assert!(!dir.join("state.pending").exists(), "{name}: pending file left behind");
        report.push(format!("before CAS (ledger S0) | {name} | {out:?}"));
    }
    // Cut after the ledger CAS: the ledger holds S1 (one slot spent).
    for (name, rename_persisted) in [("rename lost: pending S1, enc S0", false), ("rename persisted: enc S1", true)] {
        let (s, dir, st, s0) = world();
        let mut w = Wallet::open_protected(&dir, KEY, s.client()).unwrap();
        assert_eq!(w.reserve("first", &st).unwrap().unwrap().slot, 0); // commits S1
        drop(w);
        let s1 = fs::read(dir.join("state.enc")).unwrap();
        if !rename_persisted {
            fs::write(dir.join("state.enc"), &s0).unwrap();
            fs::write(dir.join("state.pending"), &s1).unwrap();
        }
        let out = reopen(&s, &dir, &st);
        assert_eq!(out, Outcome::Recovered { spent: 1 }, "{name}: committed slot must survive");
        report.push(format!("after CAS (ledger S1) | {name} | {out:?}"));
        fs::write(dir.join("state.enc"), &s0).unwrap();
        let _ = fs::remove_file(dir.join("state.pending"));
        let back = reopen(&s, &dir, &st);
        assert_eq!(back, Outcome::FailClosed, "{name}: rollback to S0 accepted");
        report.push(format!("after CAS (ledger S1) | {name}, then S0 restored | {back:?}"));
    }
    println!("{}", report.join("\n"));
    fs::write(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../results/power_loss_model.txt"), report.join("\n") + "\n").unwrap();
}
