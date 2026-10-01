//! Global device registry with ML-DSA admission (paper, Sec. III-C).
//!
//! A manufacturer certifies each device's long-term ML-DSA-65 key. A device
//! derives an epoch subtree of Lamport keys and signs (epoch, epoch root) with
//! its ML-DSA key. The registry admits a root only after checking the
//! certificate and that signature, with strictly increasing epochs per device,
//! and publishes ONE Merkle root over every admitted epoch root. All wallets
//! enrolled in a registry snapshot share that root, so the root does not
//! identify a wallet (unlike `setup_randomized_local`, whose root is local).
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use serde::{Deserialize, Serialize};
use zkmob_core::{commit, Digest, Point};
use crate::{Epoch, SignedTrace, Tree, H};

type Sk = ml_dsa::SigningKey<ml_dsa::MlDsa65>;
type Vk = ml_dsa::VerifyingKey<ml_dsa::MlDsa65>;

const CERT_CTX: &[u8] = b"zkmob/device-cert/v1";
const EPOCH_CTX: &[u8] = b"zkmob/epoch-root/v1";

fn invalid(msg: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, msg) }

fn random32() -> io::Result<[u8; 32]> {
    let mut b = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

fn sk(seed: &[u8; 32]) -> Sk { Sk::from_seed(&(*seed).into()) }

fn vk_bytes(sk: &Sk) -> Vec<u8> { sk.expanded_key().verifying_key().encode().to_vec() }

fn sign(sk: &Sk, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    sk.expanded_key().sign_deterministic(msg, ctx).expect("ML-DSA sign").encode().to_vec()
}

fn verify(vk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(vk) else { return false };
    let vk = Vk::decode(&vk);
    let Ok(enc) = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(sig) else { return false };
    ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&enc).is_some_and(|s| vk.verify_with_context(msg, ctx, &s))
}

fn epoch_msg(epoch: u64, root: &Digest) -> Vec<u8> {
    let mut m = epoch.to_le_bytes().to_vec();
    m.extend_from_slice(root);
    m
}

/// Private file write: temp file, fsync, rename, directory fsync.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()
}

/// Manufacturer signing key (private seed).
#[derive(Serialize, Deserialize)]
pub struct Manufacturer { seed: [u8; 32] }

impl Manufacturer {
    pub fn generate() -> io::Result<Self> { Ok(Self { seed: random32()? }) }
    pub fn public_key(&self) -> Vec<u8> { vk_bytes(&sk(&self.seed)) }
    fn certify(&self, device_vk: &[u8]) -> Vec<u8> { sign(&sk(&self.seed), device_vk, CERT_CTX) }
}

/// Public admission request for one epoch root.
#[derive(Clone, Serialize, Deserialize)]
pub struct Admission { pub device_vk: Vec<u8>, pub cert: Vec<u8>, pub epoch: u64, pub root: Digest, pub sig: Vec<u8> }

/// Device secrets and one-time-key state. Must be persisted after every use.
#[derive(Serialize, Deserialize)]
pub struct Device {
    mldsa_seed: [u8; 32],
    epoch_seed: [u8; 32],
    pub epoch: u64,
    pub epoch_depth: usize,
    /// Next unused one-time key of the current epoch; only grows.
    pub next_leaf: u32,
    cert: Vec<u8>,
}

impl Device {
    /// Factory provisioning: new device key certified by the manufacturer,
    /// first epoch derived. Returns the device and its admission request.
    pub fn provision(mfr: &Manufacturer, epoch_depth: usize) -> io::Result<(Self, Admission)> {
        if epoch_depth > 16 { return Err(invalid("epoch too large")); }
        let mldsa_seed = random32()?;
        let cert = mfr.certify(&vk_bytes(&sk(&mldsa_seed)));
        let dev = Self { mldsa_seed, epoch_seed: random32()?, epoch: 1, epoch_depth, next_leaf: 0, cert };
        let req = dev.admission();
        Ok((dev, req))
    }

    fn admission(&self) -> Admission {
        let key = sk(&self.mldsa_seed);
        let root = Epoch::generate(self.epoch_seed, self.epoch_depth).root();
        Admission { device_vk: vk_bytes(&key), cert: self.cert.clone(), epoch: self.epoch, root,
            sig: sign(&key, &epoch_msg(self.epoch, &root), EPOCH_CTX) }
    }

    /// Record and sign one trace with the next one-time key, and attach the
    /// registry path of this device's epoch root. The caller must persist the
    /// device (its `next_leaf` grew) BEFORE releasing the returned trace, so
    /// that a one-time key is never used twice.
    pub fn sign_trace(&mut self, reg: &Registry, traj: Vec<Point>) -> io::Result<SignedTrace> {
        let mut epoch = Epoch::resume(self.epoch_seed, self.epoch_depth, self.next_leaf);
        let (reg_index, reg_path) = reg.path(&epoch.root()).ok_or_else(|| invalid("epoch root not admitted in this registry"))?;
        if (self.next_leaf as usize) >= 1 << self.epoch_depth { return Err(invalid("epoch exhausted")); }
        let blind = random32()?;
        let c = commit::<H>(&traj, &blind);
        let (leaf_index, sig, epoch_path) = epoch.sign(&c);
        self.next_leaf = leaf_index + 1;
        Ok(SignedTrace { traj, blind, sig, leaf_index, epoch_path, reg_index, reg_path, reg_root: reg.root })
    }
}

/// Published registry snapshot: admitted epoch roots and their Merkle root.
#[derive(Serialize, Deserialize)]
pub struct Registry { pub manufacturer_vk: Vec<u8>, pub depth: usize, pub admissions: Vec<Admission>, pub root: Digest }

impl Registry {
    /// Admit requests in order. Rejects a bad certificate, a bad epoch
    /// signature, a non-increasing epoch for a device, or a duplicate root.
    pub fn build(manufacturer_vk: Vec<u8>, depth: usize, requests: Vec<Admission>) -> io::Result<Self> {
        if depth > 31 || requests.len() > 1usize << depth { return Err(invalid("registry too small")); }
        let mut last: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        let mut roots = std::collections::BTreeSet::new();
        for r in &requests {
            if !verify(&manufacturer_vk, &r.device_vk, CERT_CTX, &r.cert) { return Err(invalid("device certificate rejected")); }
            if !verify(&r.device_vk, &epoch_msg(r.epoch, &r.root), EPOCH_CTX, &r.sig) { return Err(invalid("epoch signature rejected")); }
            if last.get(&r.device_vk).is_some_and(|&e| r.epoch <= e) { return Err(invalid("epoch number not increasing")); }
            if !roots.insert(r.root) { return Err(invalid("duplicate epoch root")); }
            last.insert(r.device_vk.clone(), r.epoch);
        }
        let root = Tree::new(depth, requests.iter().map(|r| r.root).collect()).root();
        Ok(Self { manufacturer_vk, depth, admissions: requests, root })
    }

    /// Recheck every admission and the published root (e.g. by a verifier).
    pub fn verify(&self) -> bool {
        Self::build(self.manufacturer_vk.clone(), self.depth, self.admissions.clone()).is_ok_and(|r| r.root == self.root)
    }

    pub fn path(&self, epoch_root: &Digest) -> Option<(u32, Vec<Digest>)> {
        let i = self.admissions.iter().position(|a| &a.root == epoch_root)?;
        Some((i as u32, Tree::new(self.depth, self.admissions.iter().map(|a| a.root).collect()).path(i)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkmob_core::{check, merkle_root, Statement, Policy, Step, BoxZone};

    fn traj() -> Vec<Point> { (0..8).map(|i| Point { x: i * 10, y: i * 10, t: i * 5 }).collect() }

    #[test]
    fn devices_share_one_root_and_witnesses_chain_to_it() {
        let mfr = Manufacturer::generate().unwrap();
        let (mut a, ra) = Device::provision(&mfr, 3).unwrap();
        let (mut b, rb) = Device::provision(&mfr, 3).unwrap();
        let reg = Registry::build(mfr.public_key(), 8, vec![ra, rb]).unwrap();
        assert!(reg.verify());
        let (sa, sb) = (a.sign_trace(&reg, traj()).unwrap(), b.sign_trace(&reg, traj()).unwrap());
        assert_eq!(sa.reg_root, sb.reg_root, "one global root");
        assert_ne!(sa.reg_index, sb.reg_index);
        let zone = BoxZone { xmin: 0, xmax: 100, ymin: 0, ymax: 100 };
        let st = Statement { policy: Policy { steps: vec![Step { zone, max_gap: None }], avoid: None },
            reg_root: reg.root, verifier: [1; 32], budget: 2 };
        for s in [&sa, &sb] {
            assert!(check::<H>(&st, &s.witness(0)).outcome);
        }
        assert_eq!(a.next_leaf, 1, "one-time key state advanced");
        let again = a.sign_trace(&reg, traj()).unwrap();
        assert_eq!(again.leaf_index, 1, "next trace uses a fresh one-time key");
        let _ = merkle_root::<H>; // keep import used across feature sets
    }

    #[test]
    fn admission_rejects_forgeries_and_replays() {
        let mfr = Manufacturer::generate().unwrap();
        let other = Manufacturer::generate().unwrap();
        let (_d, r) = Device::provision(&mfr, 2).unwrap();
        let (_x, rogue) = Device::provision(&other, 2).unwrap();
        assert!(Registry::build(mfr.public_key(), 4, vec![rogue]).is_err(), "uncertified device");
        let mut bad_sig = r.clone();
        bad_sig.root[0] ^= 1;
        assert!(Registry::build(mfr.public_key(), 4, vec![bad_sig]).is_err(), "root not signed by the device");
        let mut replay = r.clone();
        replay.root[1] ^= 1; // distinct root, same epoch number, resigned is impossible without the key
        assert!(Registry::build(mfr.public_key(), 4, vec![r.clone(), r.clone()]).is_err(), "duplicate root");
        assert!(Registry::build(mfr.public_key(), 4, vec![r.clone(), replay]).is_err(), "forged second epoch");
        let unknown = Device::provision(&mfr, 2).unwrap().0;
        let reg = Registry::build(mfr.public_key(), 4, vec![r]).unwrap();
        let mut unknown = unknown;
        assert!(unknown.sign_trace(&reg, traj()).is_err(), "device not admitted");
    }
}
