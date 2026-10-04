//! Durable local wallet/prover. See code/WALLET_STORAGE.md for commands and
//! authentication/rollback boundaries. stdout contains ONLY a persisted receipt
//! or a public status; secret-dependent diagnostics are not a network protocol.
//!
//! Fixed-latency release (paper, Proposition on metadata, condition (iii)).
//! The reservation durably fixes a deadline = admission + `release_latency_ms`.
//! Proving runs in a worker process (`--prove-worker`) in its own process
//! group, so the external r0vm prover is its descendant. If the proof is not
//! ready at the deadline, the whole group is killed (no orphaned prover keeps
//! computing), the request is expired at the deadline (one commit), its slot
//! stays spent and no response is ever released. Otherwise the wallet waits for the
//! deadline, commits the completion, re-checks the anchor and releases. The
//! ledger thus sees reserve at admission and complete/expire at the deadline,
//! and a completed response never exists before its deadline, so a retry
//! after a crash cannot release early. A resumed pending request keeps its
//! original deadline.
//!
//! `--request-id` names a session of the HOLDER and must be chosen by the
//! holder (fresh per session, reused only to resume that session). Never pass
//! a verifier-chosen identifier: a repeated identifier returns the cached
//! proof, so a verifier that reuses one across sessions could link them
//! (paper, Definition 3 scopes identifiers by handle for this reason).
use std::{error::Error, io::Write, path::Path, sync::mpsc, time::Duration};
use host::{setup_randomized_local, load_trace_nth, wallet::Wallet, vault, anchor::Anchor, H};
use host::registry::{sign_with_device_file, Registry};
use methods::{ZKMOB_GUEST_ELF, ZKMOB_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use zkmob_core::{check, validate_policy, Journal, Policy, Statement, Witness};

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn until(deadline_ms: u64) -> Duration { Duration::from_millis(deadline_ms.saturating_sub(now_ms())) }

/// Proof in progress in a separate process group: the worker and the r0vm
/// process it starts. Its stdout is a pipe to this process only, and its
/// stderr is /dev/null, so nothing it inherits reaches the caller.
struct ProverGroup { child: std::process::Child, rx: mpsc::Receiver<std::io::Result<Vec<u8>>> }

impl ProverGroup {
    fn spawn(st: &Statement, witness: &Witness) -> Result<Self, Box<dyn Error>> {
        use std::{io::Read, os::unix::process::CommandExt, process::{Command, Stdio}};
        let mut child = Command::new(std::env::current_exe()?).arg("--prove-worker")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .process_group(0).spawn()?;
        let st_bytes = bincode::serialize(st)?;
        let mut stdin = child.stdin.take().ok_or("worker stdin")?;
        stdin.write_all(&(st_bytes.len() as u32).to_le_bytes())?;
        stdin.write_all(&st_bytes)?;
        stdin.write_all(&witness.to_bytes())?;
        drop(stdin);
        let mut out = child.stdout.take().ok_or("worker stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || { let mut b = Vec::new(); let _ = tx.send(out.read_to_end(&mut b).map(|_| b)); });
        Ok(Self { child, rx })
    }

    /// Kill the worker and every process in its group (including r0vm).
    fn kill(mut self) {
        unsafe { libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL); }
        let _ = self.child.wait();
    }
}

/// `--prove-worker`: read (statement, witness) from stdin, write the verified
/// receipt bytes to stdout.
fn prove_worker() -> Result<(), Box<dyn Error>> {
    use std::io::Read;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let n = u32::from_le_bytes(input.get(..4).ok_or("short input")?.try_into()?) as usize;
    let st: Statement = bincode::deserialize(input.get(4..4 + n).ok_or("short input")?)?;
    let witness = Witness::from_bytes(&input[4 + n..]);
    std::io::stdout().lock().write_all(&prove(&st, &witness)?)?;
    Ok(())
}

/// Prove and verify one statement; errors are strings so they cross threads.
fn prove(st: &Statement, witness: &Witness) -> Result<Vec<u8>, String> {
    let e = |x: &dyn std::fmt::Display| x.to_string();
    let expected = check::<H>(st, witness);
    let input = witness.to_bytes();
    let env = ExecutorEnv::builder().write(st).map_err(|x| e(&x))?.write_slice(&[input.len() as u32])
        .write_slice(&input).build().map_err(|x| e(&x))?;
    let receipt = default_prover().prove_with_opts(env, ZKMOB_GUEST_ELF, &ProverOpts::succinct()).map_err(|x| e(&x))?.receipt;
    receipt.verify(ZKMOB_GUEST_ID).map_err(|x| e(&x))?;
    let journal: Journal = receipt.journal.decode().map_err(|x| e(&x))?;
    if !matches!(receipt.inner, InnerReceipt::Succinct(_)) || journal != expected {
        return Err("receipt does not match reserved statement/witness".into());
    }
    bincode::serialize(&receipt).map_err(|x| e(&x))
}

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() { return Err("unset RISC0_DEV_MODE".into()); }
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--prove-worker") { return prove_worker(); }
    let get = |key: &str| -> Result<&str, Box<dyn Error>> {
        args.iter().position(|a| a == key).and_then(|i| args.get(i+1))
            .map(|s| s.as_str()).ok_or_else(|| format!("missing {key}").into())
    };
    if args.iter().any(|s| s == "--generate-key") {
        vault::generate_key(Path::new(get("--generate-key")?))?;
        println!("generated private key file (keep outside wallet backups)");
        return Ok(());
    }
    let path = Path::new(get("--wallet")?);
    let legacy = args.iter().any(|s| s == "--legacy-plaintext");
    let key = if legacy {
        if args.iter().any(|s| s == "--key-file" || s == "--anchor-url" || s == "--anchor-token") {
            return Err("legacy and protected options cannot be combined".into());
        }
        None
    } else {
        let key_path = Path::new(get("--key-file")?);
        let wallet_path = if path.exists() { path.canonicalize()? } else {
            path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).canonicalize()?.join(path.file_name().ok_or("invalid wallet path")?)
        };
        if key_path.canonicalize()?.starts_with(&wallet_path) || Path::new(get("--anchor-token")?).canonicalize()?.starts_with(&wallet_path) {
            return Err("key and anchor credentials must be outside the wallet directory".into());
        }
        Some(vault::load_key(key_path)?)
    };
    let service = || -> Result<Anchor, Box<dyn Error>> {
        let token = vault::load_key(Path::new(get("--anchor-token")?))?;
        Ok(Anchor::new(get("--anchor-url")?, &token, args.iter().any(|s| s == "--allow-loopback-http"))?)
    };
    if args.iter().any(|s| s == "--init") {
        let n: usize = get("--n")?.parse()?;
        let budget: u32 = get("--budget")?.parse()?;
        // Required, immutable. Choose it above the worst observed proving time.
        let latency_ms: u64 = get("--latency-ms")?.parse()?;
        if n < 2 { return Err("n must be at least 2".into()); }
        if latency_ms == 0 && !legacy { return Err("protected wallets need --latency-ms > 0".into()); }
        // Exists check avoids expensive provisioning; create() also checks
        // atomically, so two initialisers cannot replace the same wallet.
        if path.exists() { return Err("wallet path already exists; refusing reset".into()); }
        let k: usize = get("--trace-index").map(|k| k.parse()).unwrap_or(Ok(0))?;
        let traj = load_trace_nth(get("--traces")?, n, k);
        // Global registry (deployment) or an explicitly requested local test
        // registry. A partial global configuration is an error, never a
        // silent fallback to the weaker local mode.
        let local = args.iter().any(|s| s == "--local-registry");
        let (signed, note) = match (get("--device"), get("--registry"), local) {
            (Ok(dev_path), Ok(reg_path), false) => {
                let reg: Registry = serde_json::from_slice(&std::fs::read(reg_path)?)?;
                if !reg.verify() { return Err("registry snapshot does not verify".into()); }
                // Locked read / leaf allocation / durable counter update.
                (sign_with_device_file(Path::new(dev_path), &reg, traj)?, "initialized wallet in GLOBAL registry (ML-DSA admission)")
            }
            (Err(_), Err(_), true) => (setup_randomized_local(traj, 10, 20, 1000)?,
                "initialized randomized LOCAL registry wallet (test fixture: not ML-DSA admission; root identifies the wallet)"),
            _ => return Err("use --device and --registry together, or --local-registry alone".into()),
        };
        // Budget period in seconds (0 = lifetime cap). Fixed at enrolment.
        let period_s: u64 = get("--period-s").map(|p| p.parse()).unwrap_or(Ok(0))?;
        let mut wallet = if let Some(key) = &key {
            Wallet::create_protected_with_latency(path, signed, budget, latency_ms, **key, service()?)?
        } else { Wallet::create_with_latency(path, signed, budget, latency_ms)? };
        if period_s > 0 { wallet.set_period_len(period_s)?; }
        println!("{note}");
        return Ok(());
    }
    if args.iter().any(|s| s == "--add-trace") {
        // Another trace signed by the same device; it shares the device's
        // per-verifier budget. Global registry only (the device file keeps
        // the one-time-key counter across traces).
        let n: usize = get("--n")?.parse()?;
        let k: usize = get("--trace-index").map(|k| k.parse()).unwrap_or(Ok(0))?;
        let reg: Registry = serde_json::from_slice(&std::fs::read(get("--registry")?)?)?;
        if !reg.verify() { return Err("registry snapshot does not verify".into()); }
        let mut wallet = if let Some(key) = &key {
            Wallet::open_protected(path, **key, service()?)?
        } else { Wallet::open(path)? };
        let signed = sign_with_device_file(Path::new(get("--device")?), &reg, load_trace_nth(get("--traces")?, n, k))?;
        let i = wallet.add_trace(signed)?;
        println!("added trace {i}");
        return Ok(());
    }
    if args.iter().any(|s| ["--budget", "--traces", "--n", "--latency-ms", "--period-s", "--device", "--registry", "--trace-index", "--local-registry"].contains(&s.as_str())) {
        return Err("trace, budget and release latency are immutable; these options are init-only".into());
    }
    let policy: Policy = serde_json::from_reader(std::fs::File::open(get("--policy")?)?)?;
    // Admission depends only on the public policy, and covers the whole domain
    // the core supports, so an unsupported policy never consumes a slot.
    validate_policy(&policy)?;
    let v = get("--verifier")?;
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("verifier must be a 32-byte hex identity already authenticated by the caller".into());
    }
    let mut verifier = [0u8; 32];
    for (i, byte) in verifier.iter_mut().enumerate() { *byte = u8::from_str_radix(&v[2*i..2*i+2], 16)?; }
    let id = get("--request-id")?;
    let mut wallet = if let Some(key) = &key {
        Wallet::open_protected(path, **key, service()?)?
    } else { Wallet::open(path)? }; // lock stays held through response output
    // A retry keeps its original period; a fresh request uses the current one.
    let period = match wallet.request_period(id, &verifier) { Some(p) => p, None => wallet.current_period()? };
    let st = Statement { policy, reg_root: wallet.signed().reg_root, verifier, budget: wallet.budget(), period };
    let trace: u32 = get("--trace").map(|t| t.parse()).unwrap_or(Ok(0))?;
    let Some(reservation) = wallet.reserve_for(id, &st, trace)? else {
        println!("exhausted");
        return Ok(());
    };
    if reservation.expired {
        println!("expired");
        return Ok(());
    }
    let latency = wallet.release_latency_ms() > 0;
    let deadline = reservation.deadline_ms;
    let witness = wallet.trace(reservation.trace).ok_or("unknown trace")?.witness(reservation.slot);
    let bytes = if let Some(cached) = reservation.response { cached } else {
        if latency && now_ms() >= deadline {
            // Resumed after the deadline (e.g. a crash while proving).
            wallet.expire(id, &st)?;
            println!("expired");
            return Ok(());
        }
        let group = ProverGroup::spawn(&st, &witness)?;
        let wait = if latency { until(deadline) } else { Duration::MAX };
        let result = match group.rx.recv_timeout(wait) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Overrun: stop the prover group, then report at the deadline.
                group.kill();
                wallet.expire(id, &st)?;
                println!("expired");
                return Ok(());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::other("prover worker failed")),
        };
        let mut group = group;
        if !group.child.wait()?.success() { return Err("prover worker failed".into()); }
        let result: Result<Vec<u8>, String> = result.map_err(|e| e.to_string());
        let bytes = result?;
        if latency { std::thread::sleep(until(deadline)); }
        wallet.complete(id, &st, bytes.clone())?;
        bytes
    };
    // Verify cached responses too; corrupt cache must never be released.
    let receipt: Receipt = bincode::deserialize(&bytes)?;
    receipt.verify(ZKMOB_GUEST_ID)?;
    let journal: Journal = receipt.journal.decode()?;
    if !matches!(receipt.inner, InnerReceipt::Succinct(_)) || journal != check::<H>(&st, &witness) {
        return Err("cached receipt mismatch".into());
    }
    // The only receipt release is AFTER durable completion. A broken pipe
    // does not refund the slot; retry returns these exact persisted bytes.
    wallet.ensure_current()?; // no receipt release if anchor is unavailable/stale
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}
