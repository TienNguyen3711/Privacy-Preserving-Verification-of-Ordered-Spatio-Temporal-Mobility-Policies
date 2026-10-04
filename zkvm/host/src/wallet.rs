use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use zkmob_core::Statement;
use crate::{SignedTrace, anchor::{Anchor, Head}, vault};
use zeroize::Zeroizing;

// Test-only process termination; never enabled in default production builds.
fn commit_fault(point: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("ZKMOB_COMMIT_FAULT").as_deref() == Ok(point) {
        std::process::abort(); // no unwinding, destructors or explicit flushing
    }
    let _ = point;
}

fn invalid(msg: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, msg) }

/// Wallet format version. v2: 256-bit blind (SignedTrace) and an immutable
/// release latency. v3: each reservation persists its release deadline, so a
/// crash cannot move it. v4: receipts are stored as separate (encrypted)
/// files named by their SHA-256, referenced from the state, so the cost of a
/// request does not grow with the number of stored receipts. Older wallets
/// are rejected, never migrated: re-signing would create a new commitment,
/// and resetting budgets is forbidden. v5: one wallet per DEVICE holding
/// every trace it signed; nullifiers derive from the device budget key, so a
/// verifier's slots are shared by all traces of the device (review RR-11).
/// v6: budgets renew per period (re-review NEW-01): B slots per (verifier,
/// period), the period read from the trusted local clock.
pub const WALLET_VERSION: u32 = 6;

fn now_ms() -> io::Result<u64> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64).map_err(|_| invalid("system clock before 1970"))
}

#[derive(Serialize, Deserialize)]
struct Request {
    statement: Statement,
    /// Index of the trace this request is about.
    trace: u32,
    slot: u32,
    /// SHA-256 (hex) of the stored receipt in `receipts/`; the state, and
    /// hence the ledger digest, commits to the receipt bytes.
    response: Option<String>,
    /// Proving overran the release latency: the slot is burned and no response
    /// is ever released for this request (retries return the public status).
    expired: bool,
    /// Release deadline (Unix ms, trusted local clock), fixed durably with the
    /// reservation: admission + latency. 0 when the wallet has no latency.
    deadline_ms: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Scope { next: u32, requests: BTreeMap<String, Request> }

#[derive(Serialize, Deserialize)]
struct AnchorMeta { wallet_id: String, revision: u64 }

#[derive(Serialize, Deserialize)]
struct State {
    version: u32,
    #[serde(default)]
    anchor: Option<AnchorMeta>,
    budget: u32,
    /// Fixed release latency in milliseconds after durable admission
    /// (0 = no padding; test/legacy helper only). Immutable after creation.
    release_latency_ms: u64,
    /// Every trace of one device (same budget key, same registry root).
    traces: Vec<SignedTrace>,
    /// Budget period length in seconds (0 = one lifetime period, number 0).
    /// Fixed before the first request.
    #[serde(default)]
    period_s: u64,
    scopes: BTreeMap<String, Scope>,
}

pub struct Reservation { pub trace: u32, pub slot: u32, pub response: Option<Vec<u8>>, pub expired: bool, pub deadline_ms: u64 }

pub struct Wallet {
    dir: PathBuf,
    // Lock released by the OS on normal exit or process death, no stale PID lock.
    _lock: File,
    state: State,
    poisoned: bool,
    key: Option<Zeroizing<[u8;32]>>,
    anchor: Option<Anchor>,
    head: Option<Head>,
}

impl Wallet {
    /// Explicit creation only. An existing directory, including incomplete
    /// initialisation, is an error: never silently reset an existing wallet.
    pub fn create(path: &Path, signed: SignedTrace, budget: u32) -> io::Result<Self> {
        Self::create_inner(path, signed, budget, 0, None, None)
    }

    pub fn create_with_latency(path: &Path, signed: SignedTrace, budget: u32, latency_ms: u64) -> io::Result<Self> {
        Self::create_inner(path, signed, budget, latency_ms, None, None)
    }

    pub fn create_protected(path: &Path, signed: SignedTrace, budget: u32, key: [u8;32], anchor: Anchor) -> io::Result<Self> {
        Self::create_inner(path, signed, budget, 0, Some(Zeroizing::new(key)), Some(anchor))
    }

    pub fn create_protected_with_latency(path: &Path, signed: SignedTrace, budget: u32, latency_ms: u64, key: [u8;32], anchor: Anchor) -> io::Result<Self> {
        Self::create_inner(path, signed, budget, latency_ms, Some(Zeroizing::new(key)), Some(anchor))
    }

    fn create_inner(path: &Path, signed: SignedTrace, budget: u32, release_latency_ms: u64, key: Option<Zeroizing<[u8;32]>>, anchor: Option<Anchor>) -> io::Result<Self> {
        let meta = key.as_ref().map(|k| {
            // Stable per device under this key: a second wallet for the same
            // device (which would get a fresh budget) collides at the ledger.
            let mut bytes = b"zkmob/anchor-device/v1".to_vec();
            bytes.extend_from_slice(&zkmob_core::device_tag::<crate::H>(&signed.dev_key));
            let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, k.as_ref()), &bytes);
            AnchorMeta { wallet_id: tag.as_ref().iter().map(|b| format!("{b:02x}")).collect(), revision: 0 }
        });
        fs::DirBuilder::new().mode(0o700).create(path)?;
        let lock = OpenOptions::new().read(true).write(true).create_new(true)
            .mode(0o600).open(path.join("wallet.lock"))?;
        lock.lock()?;
        let mut wallet = Self { dir: path.to_path_buf(), _lock: lock, poisoned: false, key, anchor, head: None,
            state: State { version: WALLET_VERSION, anchor: meta, budget, release_latency_ms, traces: vec![signed], period_s: 0, scopes: BTreeMap::new() } };
        wallet.persist()?;
        File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(wallet)
    }

    /// Missing/corrupt state fails closed. Does not create files or reset caps.
    /// Keep this object alive until the response is persisted and emitted.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_inner(path, None, None)
    }

    pub fn open_protected(path: &Path, key: [u8;32], anchor: Anchor) -> io::Result<Self> {
        Self::open_inner(path, Some(Zeroizing::new(key)), Some(anchor))
    }

    fn open_inner(path: &Path, key: Option<Zeroizing<[u8;32]>>, anchor: Option<Anchor>) -> io::Result<Self> {
        let lock = OpenOptions::new().read(true).write(true).open(path.join("wallet.lock"))?;
        lock.lock()?;
        let mut head = None;
        let state: State = if let (Some(key), Some(service)) = (&key, &anchor) {
            let pending = path.join("state.pending");
            let current = path.join("state.enc");
            // If the service committed but the client crashed before rename,
            // recover ONLY the exact ciphertext named by its authoritative tip.
            if pending.exists() {
                let blob = fs::read(&pending)?;
                // A power cut before the pending file's fsync can leave it empty
                // or torn. Such a file was never committed: the ledger CAS
                // happens only after that fsync. Treat it as uncommitted.
                let staged = vault::open(key, &blob).ok()
                    .and_then(|plain| serde_json::from_slice::<State>(&plain).ok());
                let committed = match &staged {
                    Some(st) => {
                        let meta = st.anchor.as_ref().ok_or_else(|| invalid("missing anchor metadata"))?;
                        service.current(&meta.wallet_id)? == Self::snapshot_head(st, &blob)?
                    }
                    None => false,
                };
                if committed {
                    fs::rename(&pending, &current)?;
                    File::open(path)?.sync_all()?;
                } else if current.exists() {
                    // Discard the pending file only if the current snapshot is
                    // exactly the ledger tip, i.e. nothing newer was committed.
                    let oldblob = fs::read(&current)?;
                    let old: State = serde_json::from_slice(&vault::open(key, &oldblob)?)?;
                    let meta = old.anchor.as_ref().ok_or_else(|| invalid("missing anchor metadata"))?;
                    if service.current(&meta.wallet_id)? != Self::snapshot_head(&old, &oldblob)? {
                        return Err(invalid("stale/cloned wallet; anchor mismatch"));
                    }
                    fs::remove_file(&pending)?;
                    File::open(path)?.sync_all()?;
                } else { return Err(invalid("uncommitted initial snapshot; recovery required")); }
            }
            let blob = fs::read(&current)?;
            let state: State = serde_json::from_slice(&vault::open(key, &blob)?)?;
            let expected = Self::snapshot_head(&state, &blob)?;
            if service.current(&expected.wallet_id)? != expected { return Err(invalid("stale/cloned wallet; anchor mismatch")); }
            head = Some(expected);
            state
        } else {
            if path.join("state.enc").exists() { return Err(invalid("encrypted wallet requires key and online anchor")); }
            let state: State = serde_json::from_reader(File::open(path.join("state.json"))?)?;
            if state.anchor.is_some() { return Err(invalid("anchor downgrade forbidden")); }
            state
        };
        if state.version != WALLET_VERSION {
            return Err(invalid("unsupported wallet version (older wallets are not migrated)"));
        }
        let first = state.traces.first().ok_or_else(|| invalid("wallet without a trace"))?;
        if state.traces.iter().any(|t| t.dev_key != first.dev_key || t.reg_root != first.reg_root) {
            return Err(invalid("traces of different devices or registries"));
        }
        for (v, scope) in &state.scopes {
            if scope.next > state.budget || scope.requests.len() != scope.next as usize {
                return Err(invalid("corrupt wallet counter"));
            }
            let mut slots = std::collections::BTreeSet::new();
            for req in scope.requests.values() {
                if req.slot >= scope.next || !slots.insert(req.slot) || (req.expired && req.response.is_some())
                    || req.statement.budget != state.budget
                    || req.statement.reg_root != state.traces[0].reg_root
                    || req.trace as usize >= state.traces.len()
                    || Self::verifier_key(&req.statement) != *v {
                    return Err(invalid("corrupt wallet reservation"));
                }
            }
        }
        Ok(Self { dir: path.to_path_buf(), _lock: lock, state, poisoned: false, key, anchor, head })
    }

    fn persist(&mut self) -> io::Result<()> {
        let result = self.write_snapshot();
        if result.is_err() { self.poisoned = true; }
        result
    }

    fn snapshot_head(state: &State, blob: &[u8]) -> io::Result<Head> {
        let meta = state.anchor.as_ref().ok_or_else(|| invalid("missing anchor metadata"))?;
        Ok(Head { wallet_id: meta.wallet_id.clone(), revision: meta.revision,
            tip: crate::sha(&[blob]).iter().map(|b| format!("{b:02x}")).collect() })
    }

    pub fn ensure_current(&mut self) -> io::Result<()> {
        if self.poisoned { return Err(invalid("wallet handle poisoned")); }
        if let (Some(service), Some(expected)) = (&self.anchor, &self.head) {
            let result = service.current(&expected.wallet_id);
            match result {
                Ok(actual) if actual == *expected => (),
                _ => { self.poisoned = true; return Err(invalid("anchor unavailable or stale/cloned wallet")); }
            }
        }
        Ok(())
    }

    fn write_snapshot(&mut self) -> io::Result<()> {
        // Private directory + exclusive lock; overwrite only our orphan temp.
        let tmp = self.dir.join("state.pending");
        if tmp.exists() { fs::remove_file(&tmp)?; }
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        if let Some(key) = &self.key {
            if let Some(old) = &self.head {
                self.state.anchor.as_mut().ok_or_else(|| invalid("missing anchor"))?.revision =
                    old.revision.checked_add(1).ok_or_else(|| invalid("revision exhausted"))?;
            }
            let plaintext = Zeroizing::new(serde_json::to_vec(&self.state)?);
            let encrypted = vault::seal(key, &plaintext)?;
            f.write_all(&encrypted)?;
            f.sync_all()?;
            File::open(&self.dir)?.sync_all()?; // staged filename durable before remote CAS
            commit_fault("staged");
            let next = Self::snapshot_head(&self.state, &encrypted)?;
            let service = self.anchor.as_ref().ok_or_else(|| invalid("missing anchor service"))?;
            if let Some(old) = &self.head { service.advance(old, &next)?; } else { service.register(&next)?; }
            commit_fault("anchored");
            fs::rename(&tmp, self.dir.join("state.enc"))?;
            commit_fault("renamed");
            File::open(&self.dir)?.sync_all()?;
            commit_fault("synced");
            self.head = Some(next);
            Ok(())
        } else {
            serde_json::to_writer(&mut f, &self.state)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
            fs::rename(&tmp, self.dir.join("state.json"))?;
            File::open(&self.dir)?.sync_all()
        }
    }

    fn write_receipt(&mut self, hash: &str, bytes: &[u8]) -> io::Result<()> {
        let dir = self.dir.join("receipts");
        if !dir.exists() {
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
            File::open(&self.dir)?.sync_all()?;
        }
        let blob = match &self.key { Some(k) => vault::seal(k, bytes)?, None => bytes.to_vec() };
        let tmp = dir.join(format!("{hash}.tmp"));
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        let result = f.write_all(&blob).and_then(|_| f.sync_all())
            .and_then(|_| fs::rename(&tmp, dir.join(format!("{hash}.bin"))))
            .and_then(|_| File::open(&dir)?.sync_all());
        if result.is_err() { self.poisoned = true; }
        result
    }

    /// Stored receipt; fails closed if missing, undecryptable or altered.
    fn read_receipt(&self, hash: &str) -> io::Result<Vec<u8>> {
        let blob = fs::read(self.dir.join("receipts").join(format!("{hash}.bin")))?;
        let bytes = match &self.key { Some(k) => vault::open(k, &blob)?.to_vec(), None => blob };
        let actual: String = crate::sha(&[&bytes]).iter().map(|b| format!("{b:02x}")).collect();
        if actual != hash { return Err(invalid("stored receipt does not match its committed hash")); }
        Ok(bytes)
    }

    fn verifier_key(st: &Statement) -> String {
        Self::scope_key(&st.verifier, st.period)
    }

    fn scope_key(verifier: &[u8; 32], period: u32) -> String {
        let v: String = verifier.iter().map(|b| format!("{b:02x}")).collect();
        format!("{v}/{period}")
    }

    /// Set the budget period length (seconds). Only before the first request:
    /// changing it later could re-open spent periods.
    pub fn set_period_len(&mut self, period_s: u64) -> io::Result<()> {
        self.ensure_current()?;
        if !self.state.scopes.is_empty() { return Err(invalid("period length is fixed after the first request")); }
        self.state.period_s = period_s;
        self.persist()
    }
    pub fn period_len(&self) -> u64 { self.state.period_s }

    /// Current budget period from the trusted local clock.
    pub fn current_period(&self) -> io::Result<u32> {
        if self.state.period_s == 0 { return Ok(0); }
        u32::try_from(now_ms()? / 1000 / self.state.period_s).map_err(|_| invalid("period overflow"))
    }

    /// Period of an existing request id for this verifier (for retries that
    /// span a period boundary), if any.
    pub fn request_period(&self, id: &str, verifier: &[u8; 32]) -> Option<u32> {
        self.state.scopes.values().flat_map(|s| s.requests.get(id))
            .find(|r| &r.statement.verifier == verifier).map(|r| r.statement.period)
    }

    /// The first trace (wallets created with one trace).
    pub fn signed(&self) -> &SignedTrace { &self.state.traces[0] }
    pub fn trace(&self, i: u32) -> Option<&SignedTrace> { self.state.traces.get(i as usize) }
    pub fn trace_count(&self) -> u32 { self.state.traces.len() as u32 }

    /// Add another trace signed by the SAME device (same budget key and
    /// registry snapshot). Its queries share the device's per-verifier slots.
    pub fn add_trace(&mut self, signed: SignedTrace) -> io::Result<u32> {
        self.ensure_current()?;
        let first = &self.state.traces[0];
        if signed.dev_key != first.dev_key { return Err(invalid("trace from another device")); }
        if signed.reg_root != first.reg_root { return Err(invalid("trace from another registry snapshot")); }
        if self.state.traces.iter().any(|t| t.blind == signed.blind || (t.leaf_index == signed.leaf_index && t.reg_index == signed.reg_index)) {
            return Err(invalid("trace or one-time key already in the wallet"));
        }
        self.state.traces.push(signed);
        self.persist()?;
        Ok(self.state.traces.len() as u32 - 1)
    }
    pub fn budget(&self) -> u32 { self.state.budget }
    pub fn release_latency_ms(&self) -> u64 { self.state.release_latency_ms }
    /// Slots spent for this statement's verifier (read-only; for audits/tests).
    pub fn spent(&self, st: &Statement) -> u32 {
        self.state.scopes.get(&Self::verifier_key(st)).map_or(0, |s| s.next)
    }

    /// Statement must have been publicly validated and V authenticated by the
    /// caller. Persist before policy evaluation, proof generation or release.
    /// None = exhausted. Same ID/context = retry, even after exhaustion.
    pub fn reserve(&mut self, id: &str, st: &Statement) -> io::Result<Option<Reservation>> {
        self.reserve_for(id, st, 0)
    }

    /// Reserve a slot for a query about trace `trace`. Slots belong to the
    /// device and verifier, not to the trace.
    pub fn reserve_for(&mut self, id: &str, st: &Statement, trace: u32) -> io::Result<Option<Reservation>> {
        self.ensure_current()?;
        if id.is_empty() || id.len() > 1024 { return Err(invalid("invalid request id")); }
        if st.budget != self.state.budget || st.reg_root != self.state.traces[0].reg_root {
            return Err(invalid("immutable budget/root mismatch"));
        }
        if trace as usize >= self.state.traces.len() { return Err(invalid("unknown trace")); }
        let scope = self.state.scopes.entry(Self::verifier_key(st)).or_default();
        if let Some(req) = scope.requests.get(id) {
            if req.statement != *st || req.trace != trace { return Err(invalid("request id is bound to another statement or trace")); }
            let (slot, expired, deadline_ms, hash) = (req.slot, req.expired, req.deadline_ms, req.response.clone());
            let response = hash.map(|h| self.read_receipt(&h)).transpose()?;
            return Ok(Some(Reservation { trace, slot, response, expired, deadline_ms }));
        }
        if scope.next == self.state.budget { return Ok(None); }
        // A fresh request may only spend the CURRENT period's budget; a
        // verifier naming another period would otherwise get fresh slots.
        if st.period != self.current_period()? { return Err(invalid("statement period is not the current period")); }
        let latency = self.state.release_latency_ms;
        let deadline_ms = if latency == 0 { 0 } else { now_ms()? + latency };
        let scope = self.state.scopes.get_mut(&Self::verifier_key(st)).expect("scope exists");
        let slot = scope.next;
        scope.next += 1;
        scope.requests.insert(id.to_owned(), Request { statement: st.clone(), trace, slot, response: None, expired: false, deadline_ms });
        self.persist()?;
        Ok(Some(Reservation { trace, slot, response: None, expired: false, deadline_ms }))
    }

    /// Mark a pending request as expired because its proof was not ready by
    /// the release deadline. The slot stays spent and the request never
    /// releases a response. Idempotent. A completed response may already have
    /// been released, so completed requests cannot expire.
    pub fn expire(&mut self, id: &str, st: &Statement) -> io::Result<()> {
        self.ensure_current()?;
        let req = self.state.scopes.get_mut(&Self::verifier_key(st))
            .and_then(|s| s.requests.get_mut(id)).ok_or_else(|| invalid("unreserved request"))?;
        if req.statement != *st { return Err(invalid("statement mismatch")); }
        if req.expired { return Ok(()); }
        if req.response.is_some() { return Err(invalid("completed request cannot expire")); }
        req.expired = true;
        self.persist()
    }

    /// Persist the already verified response BEFORE sending it. Never refund
    /// a failed/pending reservation. A completed response is immutable.
    pub fn complete(&mut self, id: &str, st: &Statement, response: Vec<u8>) -> io::Result<()> {
        self.ensure_current()?;
        let req = self.state.scopes.get_mut(&Self::verifier_key(st))
            .and_then(|s| s.requests.get_mut(id)).ok_or_else(|| invalid("unreserved request"))?;
        if req.statement != *st { return Err(invalid("statement mismatch")); }
        if req.expired { return Err(invalid("request expired; response is never released")); }
        // Completion is committed no earlier than the deadline, so a stored
        // response is releasable at once, even by a retry after a crash.
        if now_ms()? < req.deadline_ms { return Err(invalid("completion before the release deadline")); }
        let hash: String = crate::sha(&[&response]).iter().map(|b| format!("{b:02x}")).collect();
        if let Some(old) = &req.response {
            return if old == &hash { Ok(()) } else { Err(invalid("response is immutable")) };
        }
        // The receipt file is durable before the state that references it.
        self.write_receipt(&hash, &response)?;
        let req = self.state.scopes.get_mut(&Self::verifier_key(st))
            .and_then(|s| s.requests.get_mut(id)).ok_or_else(|| invalid("unreserved request"))?;
        req.response = Some(hash);
        self.persist()
    }
}
