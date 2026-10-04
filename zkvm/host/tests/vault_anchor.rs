//! Integration with an independent Python ledger process, no fake anchor.
use std::{fs, io::{BufRead, BufReader}, path::PathBuf, process::{Child, Command, Stdio}, time::{SystemTime, UNIX_EPOCH}};
use host::{anchor::Anchor, vault, wallet::Wallet, setup_randomized_local, policy_between, sha};
use zkmob_core::{Point, Statement};

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct Service { root: PathBuf, child: Child, url: String, token: [u8;32] }
impl Service {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("zkmob-anchor-{}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../python/zkmob/anchor_service.py");
        vault::generate_key(&root.join("token")).unwrap();
        let token = *vault::load_key(&root.join("token")).unwrap();
        assert!(Command::new("python3").arg(&script).args(["--init", "--state-dir"]).arg(root.join("ledger")).status().unwrap().success());
        let mut child = Command::new("python3").arg(script).arg("--state-dir").arg(root.join("ledger"))
            .arg("--token-file").arg(root.join("token")).args(["--port", "0"])
            .stdout(Stdio::piped()).spawn().unwrap();
        let mut line = String::new(); BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port = serde_json::from_str::<serde_json::Value>(&line).expect("ledger started")["port"].as_u64().unwrap();
        Self { root, child, url: format!("http://127.0.0.1:{port}"), token }
    }
    fn client(&self) -> Anchor { Anchor::new(&self.url, &self.token, true).unwrap() }
    fn create(&self, name: &str) -> Wallet {
        Wallet::create_protected(&self.root.join(name), signed(), 2, [7;32], self.client()).unwrap()
    }
}
impl Drop for Service { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = fs::remove_dir_all(&self.root); } }
fn signed() -> host::SignedTrace {
    setup_randomized_local((0..8).map(|i| Point{x:100*i,y:100*i,t:10*i}).collect(), 2, 4, 2).unwrap()
}
fn st(w: &Wallet) -> Statement { Statement { policy: policy_between(&w.signed().traj,1,6,2.), reg_root:w.signed().reg_root, verifier:sha(&[b"v"]), budget:w.budget(), period:0 } }

#[test]
fn authenticated_encryption_and_key_handling() {
    let key = [8;32]; let plain = b"private trajectory and budget";
    let a = vault::seal(&key, plain).unwrap(); let b = vault::seal(&key, plain).unwrap();
    assert_ne!(a,b);
    assert!(!a.windows(plain.len()).any(|s|s==plain));
    assert_eq!(vault::open(&key,&a).unwrap().as_slice(),plain);
    assert!(vault::open(&[9;32],&a).is_err());
    for i in [0,10,a.len()-1] { let mut bad=a.clone(); bad[i]^=1; assert!(vault::open(&key,&bad).is_err()); }
    assert!(vault::open(&key,&a[..30]).is_err());
}

#[test]
fn rollback_clone_and_downgrade_are_rejected() {
    let s = Service::new(); let mut original = s.create("original"); let statement = st(&original);
    let original_path=s.root.join("original"); let clone_path=s.root.join("clone");
    fs::create_dir(&clone_path).unwrap();
    fs::copy(original_path.join("wallet.lock"),clone_path.join("wallet.lock")).unwrap();
    fs::copy(original_path.join("state.enc"),clone_path.join("state.enc")).unwrap();
    let old=fs::read(original_path.join("state.enc")).unwrap();
    let mut clone = Wallet::open_protected(&clone_path,[7;32],s.client()).unwrap();
    original.reserve("first", &statement).unwrap();
    assert!(clone.reserve("competing", &statement).is_err());
    drop(clone);
    assert!(Wallet::open_protected(&clone_path,[7;32],s.client()).is_err());
    drop(original);
    fs::write(original_path.join("state.enc"),old).unwrap();
    assert!(Wallet::open_protected(&original_path,[7;32],s.client()).is_err());
    assert!(Wallet::open(&clone_path).is_err());
}

#[test]
fn restart_cached_response_and_no_plaintext_files() {
    let s=Service::new(); let mut w=s.create("w"); let statement=st(&w);
    w.reserve("r",&statement).unwrap(); w.complete("r",&statement,b"receipt opaque test".to_vec()).unwrap(); drop(w);
    let path=s.root.join("w");
    assert!(!path.join("state.json").exists()); assert!(!path.join("state.pending").exists());
    let mut w=Wallet::open_protected(&path,[7;32],s.client()).unwrap();
    assert_eq!(w.reserve("r",&statement).unwrap().unwrap().response.unwrap(), b"receipt opaque test");
    assert_eq!(w.reserve("r2",&statement).unwrap().unwrap().slot,1);
    assert!(w.reserve("r3",&statement).unwrap().is_none());
    drop(w);
    assert!(Wallet::open_protected(&path,[9;32],s.client()).is_err());
}

#[test]
fn cannot_reenrol_same_device_under_same_key() {
    // v5: the ledger identity is the device (its budget tag), so a second
    // wallet for the same device, which would start with a fresh budget, is
    // rejected; another device gets its own identity.
    let s=Service::new();
    let device=signed();
    drop(Wallet::create_protected(&s.root.join("first"),device.clone(),2,[7;32],s.client()).unwrap());
    assert!(Wallet::create_protected(&s.root.join("second"),device,99,[7;32],s.client()).is_err());
    assert!(Wallet::create_protected(&s.root.join("other"),signed(),2,[7;32],s.client()).is_ok());
}

#[test]
fn recovery_after_remote_commit_before_local_rename() {
    let s=Service::new(); let mut w=s.create("w"); let statement=st(&w);
    w.reserve("r",&statement).unwrap(); drop(w);
    let path=s.root.join("w");
    // Exact filesystem state of a committed staged file with no local rename.
    fs::rename(path.join("state.enc"),path.join("state.pending")).unwrap();
    let mut w=Wallet::open_protected(&path,[7;32],s.client()).unwrap();
    assert_eq!(w.reserve("r",&statement).unwrap().unwrap().slot,0);
    assert_eq!(w.reserve("r2",&statement).unwrap().unwrap().slot,1);
}

#[test]
fn uncommitted_stage_is_discarded_without_resetting_head() {
    let s=Service::new(); drop(s.create("w")); let path=s.root.join("w");
    let blob=fs::read(path.join("state.enc")).unwrap();
    let mut state:serde_json::Value=serde_json::from_slice(&vault::open(&[7;32],&blob).unwrap()).unwrap();
    state["anchor"]["revision"]=1.into();
    fs::write(path.join("state.pending"),vault::seal(&[7;32],&serde_json::to_vec(&state).unwrap()).unwrap()).unwrap();
    let w=Wallet::open_protected(&path,[7;32],s.client()).unwrap();
    assert_eq!(w.budget(),2); assert!(!path.join("state.pending").exists());
    assert_eq!(fs::read(path.join("state.enc")).unwrap(),blob);
}

#[test]
fn wrong_token_and_offline_fail_closed() {
    let mut s=Service::new(); let mut w=s.create("w"); let statement=st(&w);
    let bad=Anchor::new(&s.url,&[0;32],true).unwrap();
    assert!(bad.current(&"0".repeat(64)).is_err());
    assert!(Anchor::new(&s.url,&s.token,false).is_err());
    s.child.kill().unwrap(); s.child.wait().unwrap();
    assert!(w.reserve("r",&statement).is_err());
    assert!(w.ensure_current().is_err()); drop(w);
    assert!(Wallet::open_protected(&s.root.join("w"),[7;32],s.client()).is_err());
}

#[test]
fn atomic_compare_and_swap_allows_only_one_concurrent_branch() {
    use host::anchor::Head;
    use std::sync::{Arc, Barrier};
    let s=Service::new();
    let old=Head {wallet_id:"a".repeat(64),revision:0,tip:"b".repeat(64)};
    s.client().register(&old).unwrap();
    let barrier=Arc::new(Barrier::new(2));
    let children:Vec<_>=(0..2).map(|i| {
        let client=s.client(); let old=old.clone(); let barrier=barrier.clone();
        std::thread::spawn(move || {
            let new=Head {wallet_id:old.wallet_id.clone(),revision:1,tip:if i==0 {"c".repeat(64)} else {"d".repeat(64)}};
            barrier.wait(); let won=client.advance(&old,&new).is_ok();
            if won { client.advance(&old,&new).unwrap(); } // idempotent retry
            won
        })
    }).collect();
    assert_eq!(children.into_iter().map(|t| t.join().unwrap()).filter(|won| *won).count(), 1);
}

#[cfg(feature = "fault-injection")]
#[test]
fn crash_worker() {
    let Ok(root) = std::env::var("ZKMOB_CRASH_ROOT") else { return; };
    let root = PathBuf::from(root);
    let token = vault::load_key(&root.join("token")).unwrap();
    let client = Anchor::new(&std::env::var("ZKMOB_CRASH_URL").unwrap(), &token, true).unwrap();
    let mut w = Wallet::open_protected(&root.join("w"), [7;32], client).unwrap();
    let statement = st(&w);
    if std::env::var("ZKMOB_CRASH_OP").unwrap() == "reserve" {
        w.reserve("r", &statement).unwrap();
    } else {
        w.complete("r", &statement, b"persisted response".to_vec()).unwrap();
    }
    panic!("fault point did not terminate worker");
}

#[cfg(feature = "fault-injection")]
#[test]
fn process_crashes_at_every_commit_boundary_preserve_budget() {
    use std::os::unix::process::ExitStatusExt;
    for operation in ["reserve", "complete"] {
        for point in ["staged", "anchored", "renamed", "synced"] {
            let s = Service::new();
            let mut w = s.create("w"); let statement = st(&w);
            if operation == "complete" { w.reserve("r", &statement).unwrap(); }
            drop(w);
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "crash_worker", "--nocapture"])
                .env("ZKMOB_CRASH_ROOT", &s.root).env("ZKMOB_CRASH_URL", &s.url)
                .env("ZKMOB_CRASH_OP", operation).env("ZKMOB_COMMIT_FAULT", point)
                .output().unwrap();
            assert_eq!(output.status.signal(), Some(6), "{operation}/{point}: expected SIGABRT");
            let mut w = Wallet::open_protected(&s.root.join("w"), [7;32], s.client()).unwrap();
            let blob = fs::read(s.root.join("w/state.enc")).unwrap();
            let state: serde_json::Value = serde_json::from_slice(&vault::open(&[7;32], &blob).unwrap()).unwrap();
            let scope = &state["scopes"][statement.verifier.iter().map(|b| format!("{b:02x}")).collect::<String>()];
            let committed_reservation = operation == "complete" || point != "staged";
            assert_eq!(scope["next"].as_u64().unwrap_or(0), u64::from(committed_reservation), "{operation}/{point}: recovered counter");
            let reservation = w.reserve("r", &statement).unwrap().unwrap();
            assert_eq!(reservation.slot, 0);
            let completed = operation == "complete" && point != "staged";
            assert_eq!(reservation.response, completed.then(|| b"persisted response".to_vec()));
            assert_eq!(w.reserve("second", &statement).unwrap().unwrap().slot, 1);
            assert!(w.reserve("third", &statement).unwrap().is_none());
            assert!(!s.root.join("w/state.pending").exists());
        }
    }
}

impl Service {
    fn restart(&mut self) {
        self.child.kill().unwrap(); self.child.wait().unwrap();
        let port = self.url.rsplit(':').next().unwrap();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../python/zkmob/anchor_service.py");
        self.child = Command::new("python3").arg(script).arg("--state-dir").arg(self.root.join("ledger"))
            .arg("--token-file").arg(self.root.join("token")).args(["--port", port])
            .stdout(Stdio::piped()).spawn().unwrap();
        let mut line = String::new();
        BufReader::new(self.child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&line).unwrap()["port"].is_number());
    }
}

#[test]
fn ledger_hard_restart_preserves_completed_and_pending_budget() {
    let mut s = Service::new(); let mut w = s.create("w"); let statement = st(&w);
    w.reserve("done", &statement).unwrap();
    w.complete("done", &statement, b"cached".to_vec()).unwrap();
    w.reserve("pending", &statement).unwrap(); drop(w);
    s.restart();
    let mut w = Wallet::open_protected(&s.root.join("w"), [7;32], s.client()).unwrap();
    assert_eq!(w.reserve("done", &statement).unwrap().unwrap().response.unwrap(), b"cached");
    assert_eq!(w.reserve("pending", &statement).unwrap().unwrap().slot, 1);
    assert!(w.reserve("new", &statement).unwrap().is_none());
}

#[test]
fn twelve_wallet_clones_compete_without_forking_budget() {
    use std::sync::{Arc, Barrier};
    let s = Service::new(); drop(s.create("original"));
    let barrier = Arc::new(Barrier::new(12));
    let children: Vec<_> = (0..12).map(|i| {
        let path = s.root.join(format!("clone-{i}")); fs::create_dir(&path).unwrap();
        for file in ["wallet.lock", "state.enc"] { fs::copy(s.root.join("original").join(file), path.join(file)).unwrap(); }
        let mut w = Wallet::open_protected(&path, [7;32], s.client()).unwrap();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let statement = st(&w); barrier.wait();
            let won = w.reserve(&format!("r-{i}"), &statement).is_ok();
            if won {
                assert_eq!(w.reserve("next", &statement).unwrap().unwrap().slot, 1);
                assert!(w.reserve("excess", &statement).unwrap().is_none());
            } else { assert!(w.ensure_current().is_err()); }
            won
        })
    }).collect();
    assert_eq!(children.into_iter().map(|t| t.join().unwrap()).filter(|won| *won).count(), 1);
    assert!(Wallet::open_protected(&s.root.join("original"), [7;32], s.client()).is_err());
}

#[test]
fn lost_commit_reply_then_ledger_restart_recovers_exact_pending_snapshot() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    for complete in [false, true] {
        let mut s = Service::new(); let mut w = s.create("w"); let statement = st(&w);
        if complete { w.reserve("r", &statement).unwrap(); } drop(w);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_url = format!("http://{}", listener.local_addr().unwrap());
        let upstream = s.url.clone();
        // Forward requests faithfully but close the connection after the server
        // confirms /advance: the client cannot know whether commit succeeded.
        let proxy = std::thread::spawn(move || {
            let client = reqwest::blocking::Client::new();
            for socket in listener.incoming() {
                let mut socket = socket.unwrap();
                socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new(); reader.read_line(&mut line).unwrap();
                let parts: Vec<_> = line.split_whitespace().collect();
                let method = parts[0].to_owned(); let route = parts[1].to_owned();
                let mut length = 0; let mut auth = String::new();
                loop {
                    let mut line = String::new(); reader.read_line(&mut line).unwrap();
                    if line == "\r\n" { break; }
                    let (name, value) = line.split_once(':').unwrap();
                    if name.eq_ignore_ascii_case("content-length") { length = value.trim().parse().unwrap(); }
                    if name.eq_ignore_ascii_case("authorization") { auth = value.trim().to_owned(); }
                }
                let mut body = vec![0; length]; reader.read_exact(&mut body).unwrap();
                let response = client.request(method.parse().unwrap(), format!("{upstream}{route}"))
                    .header("Authorization", auth).body(body).send().unwrap();
                assert!(response.status().is_success());
                let bytes = response.bytes().unwrap();
                if route == "/advance" { return; }
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
                socket.write_all(&bytes).unwrap();
            }
        });
        let client = Anchor::new(&proxy_url, &s.token, true).unwrap();
        let mut w = Wallet::open_protected(&s.root.join("w"), [7;32], client).unwrap();
        if complete { assert!(w.complete("r", &statement, b"cached".to_vec()).is_err()); }
        else { assert!(w.reserve("r", &statement).is_err()); }
        assert!(w.ensure_current().is_err()); drop(w); proxy.join().unwrap();
        assert!(s.root.join("w/state.pending").exists());
        s.restart();
        let mut w = Wallet::open_protected(&s.root.join("w"), [7;32], s.client()).unwrap();
        let r = w.reserve("r", &statement).unwrap().unwrap();
        assert_eq!(r.slot, 0); assert_eq!(r.response, complete.then(|| b"cached".to_vec()));
        assert_eq!(w.reserve("next", &statement).unwrap().unwrap().slot, 1);
        assert!(w.reserve("excess", &statement).unwrap().is_none());
        assert!(!s.root.join("w/state.pending").exists());
    }
}

#[test]
fn seeded_state_machine_matches_reference_across_restarts() {
    use std::collections::BTreeMap;
    for seed in [1u64, 7, 42, 2026] {
        let mut s = Service::new(); let mut w = s.create("w");
        let base = st(&w);
        let mut model: BTreeMap<(u8, String), (u32, Option<Vec<u8>>)> = BTreeMap::new();
        let mut rng = seed;
        for step in 0..120 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let v = ((rng >> 32) % 3) as u8;
            let id = format!("r{}", (rng >> 40) % 5);
            let mut statement = base.clone(); statement.verifier = [v;32];
            let key = (v, id.clone());
            match (rng >> 48) % 4 {
                0 | 1 => {
                    let actual = w.reserve(&id, &statement).unwrap();
                    let count = model.keys().filter(|(scope, _)| *scope == v).count() as u32;
                    if !model.contains_key(&key) && count < 2 { model.insert(key.clone(), (count, None)); }
                    assert_eq!(actual.map(|r| (r.slot, r.response)), model.get(&key).cloned(), "seed {seed} step {step}");
                }
                2 => {
                    let result = w.complete(&id, &statement, b"answer".to_vec());
                    if let Some(entry) = model.get_mut(&key) {
                        result.unwrap(); entry.1 = Some(b"answer".to_vec());
                    } else { assert!(result.is_err()); }
                }
                _ => {
                    if model.contains_key(&key) {
                        statement.policy = policy_between(&w.signed().traj, 0, 2, 0.5);
                        assert!(w.reserve(&id, &statement).is_err());
                    }
                }
            }
            if step % 10 == 9 {
                drop(w);
                if step % 30 == 29 { s.restart(); }
                w = Wallet::open_protected(&s.root.join("w"), [7;32], s.client()).unwrap();
            }
            // Check persisted state independently of retries (which can mutate it).
            let blob = fs::read(s.root.join("w/state.enc")).unwrap();
            let state: serde_json::Value = serde_json::from_slice(&vault::open(&[7;32], &blob).unwrap()).unwrap();
            for v in 0..3u8 {
                let scope = &state["scopes"][format!("{}/0", format!("{v:02x}").repeat(32))];
                let entries: Vec<_> = model.iter().filter(|((scope, _), _)| *scope == v).collect();
                assert_eq!(scope["next"].as_u64().unwrap_or(0), entries.len() as u64);
                for ((_, id), (slot, response)) in entries {
                    assert_eq!(scope["requests"][id]["slot"].as_u64(), Some(*slot as u64));
                    // v4: the state commits to the receipt's SHA-256; the receipt is a separate encrypted file.
                    let expected = response.as_ref().map(|r: &Vec<u8>| sha(&[r.as_slice()]).iter().map(|b| format!("{b:02x}")).collect::<String>());
                    assert_eq!(scope["requests"][id]["response"], serde_json::to_value(&expected).unwrap());
                    if let Some(h) = expected {
                        let blob = fs::read(s.root.join(format!("w/receipts/{h}.bin"))).unwrap();
                        assert_eq!(&*vault::open(&[7;32], &blob).unwrap(), response.as_ref().unwrap().as_slice());
                    }
                }
            }
        }
    }
}

#[test]
fn protected_storage_failure_poisoning_and_truncated_snapshots_fail_closed() {
    for completion in [false, true] {
        let s = Service::new(); let mut w = s.create("w"); let statement = st(&w);
        if completion { w.reserve("r", &statement).unwrap(); }
        let path = s.root.join("w"); let old = fs::read(path.join("state.enc")).unwrap();
        // An unremovable staging pathname induces an actual filesystem error.
        fs::create_dir(path.join("state.pending")).unwrap();
        let result = if completion { w.complete("r", &statement, b"answer".to_vec()) }
                     else { w.reserve("r", &statement).map(|_| ()) };
        assert!(result.is_err()); assert!(w.ensure_current().is_err());
        assert!(w.reserve("other", &statement).is_err()); drop(w);
        assert_eq!(fs::read(path.join("state.enc")).unwrap(), old);
        fs::remove_dir(path.join("state.pending")).unwrap();
        let mut w = Wallet::open_protected(&path, [7;32], s.client()).unwrap();
        let r = w.reserve("r", &statement).unwrap().unwrap();
        assert_eq!(r.slot, 0); assert!(r.response.is_none()); drop(w);
        let good = fs::read(path.join("state.enc")).unwrap();
        for len in [0, 20, good.len()-1] {
            fs::write(path.join("state.enc"), &good[..len]).unwrap();
            assert!(Wallet::open_protected(&path, [7;32], s.client()).is_err());
        }
        fs::write(path.join("state.enc"), &good).unwrap();
        let mut w = Wallet::open_protected(&path, [7;32], s.client()).unwrap();
        assert_eq!(w.reserve("next", &statement).unwrap().unwrap().slot, 1);
        assert!(w.reserve("excess", &statement).unwrap().is_none());
    }
}
