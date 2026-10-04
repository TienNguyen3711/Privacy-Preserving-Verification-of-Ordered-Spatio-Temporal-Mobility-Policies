//! Device signatures for roadmap step 6 (claims N3 / N4).
//!
//! Two ways to authenticate the trajectory commitment C:
//!
//! * **B2 (Bogdanov et al. 2025 style), `B2Signer`:** the device signs C with
//!   a standard signature (ECDSA P-256 or ML-DSA-65, FIPS 204) and the
//!   verifier checks it outside the circuit. C, the signature and the device
//!   key are shown with every proof, so all proofs about one trace (and, via
//!   the key, all traces of one device) are linkable.
//!
//! * **Unlinkable (ours), instantiation (c):** the device signs C with a
//!   circuit-friendly hash-based signature: Lamport one-time keys over
//!   Poseidon, organised in small per-epoch Merkle trees ("epoch subtrees",
//!   2^h leaves, stateful: one leaf per trace, never reused). Each epoch
//!   root is certified by the device's long-term ML-DSA-65 key, which in
//!   turn carries a manufacturer ML-DSA-65 certificate. The registry checks
//!   both outside the circuit and publishes the Merkle root R of all epoch
//!   roots. A proof shows only the policy and R: C, the signature, the epoch
//!   root and both authentication paths stay in the witness (`unlinkable.rs`).
//!
//!   This replaces a monolithic 2^20-leaf device tree (hours of key
//!   generation) by 2^h-leaf subtrees generated on demand, WITHOUT a second
//!   in-circuit signature (the upper level of an XMSS^MT hypertree would
//!   cost another Lamport verification inside the proof).
//!
//! Security notes. Lamport over a 254-bit message is one-time EUF-CMA if
//! Poseidon is one-way (about 127-bit security against Grover). The message
//! is C itself, so no extra message hash is needed. All Poseidon calls are
//! domain-separated by a leading tag. Everything here uses only hashing and
//! ML-DSA, so it is plausibly post-quantum. The proof system is not yet:
//! Groth16/BN254 is a stand-in until the STARK back end (step 7).

use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::commit::poseidon_config;

pub const TAG_SK: u64 = 0x5eed; // legacy Poseidon PRF (benchmark only)
pub const TAG_OTS: u64 = 0x0751;
pub const TAG_PK: u64 = 0x07b5;
pub const TAG_NODE: u64 = 0x40de;
/// Device budget tag K_D = H(k_D) and registry leaf H(E || K_D) (review RR-11).
pub const TAG_DEVKEY: u64 = 0xde4e;
pub const TAG_REGLEAF: u64 = 0x1eaf;
const BUDGET_CTX: &[u8] = b"zkmob/budget-tag/v1";

/// Context string for manufacturer certificates (FIPS 204 `ctx`).
pub const CERT_CTX: &[u8] = b"zkmob/device-cert/v1";
/// Context string for a device's ML-DSA signature on an epoch root.
pub const EPOCH_CTX: &[u8] = b"zkmob/epoch-root/v1";
/// Context string for B2 ML-DSA signatures on commitments.
pub const SIG_CTX: &[u8] = b"zkmob/trace-commitment/v1";

// --------------------------------------------------------------------------
// Poseidon with domain tags
// --------------------------------------------------------------------------

/// Native Poseidon hasher; holds the (expensive to derive) parameters.
#[derive(Clone)]
pub struct Hasher<F: PrimeField> {
    pub cfg: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Hasher<F> {
    pub fn new() -> Self {
        Hasher { cfg: poseidon_config::<F>() }
    }

    /// H_tag(xs) = Poseidon(tag || xs).
    pub fn hash(&self, tag: u64, xs: &[F]) -> F {
        let mut v = Vec::with_capacity(xs.len() + 1);
        v.push(F::from(tag));
        v.extend_from_slice(xs);
        let mut s = PoseidonSponge::<F>::new(&self.cfg);
        s.absorb(&v);
        s.squeeze_field_elements::<F>(1)[0]
    }

    pub fn node(&self, l: F, r: F) -> F {
        self.hash(TAG_NODE, &[l, r])
    }
}

impl<F: PrimeField + Absorb> Default for Hasher<F> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hash_gadget<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    tag: u64,
    xs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut v = Vec::with_capacity(xs.len() + 1);
    v.push(FpVar::constant(F::from(tag)));
    v.extend_from_slice(xs);
    let mut s = PoseidonSpongeVar::<F>::new(cs, cfg);
    s.absorb(&v)?;
    Ok(s.squeeze_field_elements(1)?.remove(0))
}

/// Canonical little-endian bits of a field element (MODULUS_BIT_SIZE bits),
/// matching the strict in-circuit `to_bits_le`.
pub fn msg_bits<F: PrimeField>(m: &F) -> Vec<bool> {
    let mut b = m.into_bigint().to_bits_le();
    b.truncate(F::MODULUS_BIT_SIZE as usize);
    b
}

pub fn field_bytes<F: PrimeField>(x: &F) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

// --------------------------------------------------------------------------
// Lamport one-time signature over Poseidon
// --------------------------------------------------------------------------

#[derive(Clone)]
pub struct OtsKey<F: PrimeField> {
    pre: Vec<[F; 2]>,
    pub pk: Vec<[F; 2]>,
    pub pk_hash: F,
}

#[derive(Clone, Debug)]
pub struct OtsSig<F: PrimeField> {
    /// Preimage for the message bit at each position.
    pub reveal: Vec<F>,
    /// Public value for the other bit at each position.
    pub other: Vec<F>,
}

/// Build a one-time key from its 2 x 254 secret preimages.
fn ots_from_pre<F: PrimeField + Absorb>(h: &Hasher<F>, pre: Vec<[F; 2]>) -> OtsKey<F> {
    let pk: Vec<[F; 2]> = pre.iter().map(|s| [h.hash(TAG_OTS, &[s[0]]), h.hash(TAG_OTS, &[s[1]])]).collect();
    let flat: Vec<F> = pk.iter().flat_map(|p| [p[0], p[1]]).collect();
    let pk_hash = h.hash(TAG_PK, &flat);
    OtsKey { pre, pk, pk_hash }
}

/// Secret preimage (leaf, position i, bit b) = SHA-512(domain || seed ||
/// leaf || 2i+b) reduced into the field. The secrets never enter a circuit,
/// so a fast native PRF replaces Poseidon here (about 40% less key
/// generation work); only the public values H(s) must be Poseidon.
pub fn ots_secret<F: PrimeField>(seed: &[u8; 32], leaf: u64, idx: u64) -> F {
    use sha2::{Digest, Sha512};
    let d = Sha512::new()
        .chain_update(b"zkmob/ots-sk/v1")
        .chain_update(seed)
        .chain_update(leaf.to_le_bytes())
        .chain_update(idx.to_le_bytes())
        .finalize();
    F::from_le_bytes_mod_order(&d)
}

/// Derive the one-time key of `leaf` from the (epoch) seed.
pub fn ots_keygen<F: PrimeField + Absorb>(h: &Hasher<F>, seed: &[u8; 32], leaf: u64) -> OtsKey<F> {
    let nbits = F::MODULUS_BIT_SIZE as u64;
    let pre = (0..nbits).map(|i| [ots_secret(seed, leaf, 2 * i), ots_secret(seed, leaf, 2 * i + 1)]).collect();
    ots_from_pre(h, pre)
}

/// Previous derivation (secrets via Poseidon), kept only to benchmark the
/// change in `keygen_bench`.
pub fn ots_keygen_poseidon_prf<F: PrimeField + Absorb>(h: &Hasher<F>, seed: F, leaf: u64) -> OtsKey<F> {
    let nbits = F::MODULUS_BIT_SIZE as u64;
    let pre = (0..nbits)
        .map(|i| {
            [h.hash(TAG_SK, &[seed, F::from(leaf), F::from(2 * i)]), h.hash(TAG_SK, &[seed, F::from(leaf), F::from(2 * i + 1)])]
        })
        .collect();
    ots_from_pre(h, pre)
}

pub fn ots_sign<F: PrimeField>(key: &OtsKey<F>, m: &F) -> OtsSig<F> {
    let bits = msg_bits(m);
    let reveal = bits.iter().enumerate().map(|(i, &b)| key.pre[i][b as usize]).collect();
    let other = bits.iter().enumerate().map(|(i, &b)| key.pk[i][1 - b as usize]).collect();
    OtsSig { reveal, other }
}

/// Recompute the one-time public-key hash from a message and signature
/// (verification = compare it with the expected leaf).
pub fn ots_pk_hash<F: PrimeField + Absorb>(h: &Hasher<F>, m: &F, sig: &OtsSig<F>) -> F {
    let mut flat = Vec::with_capacity(2 * sig.reveal.len());
    for (i, b) in msg_bits(m).into_iter().enumerate() {
        let hv = h.hash(TAG_OTS, &[sig.reveal[i]]);
        if b {
            flat.extend([sig.other[i], hv]);
        } else {
            flat.extend([hv, sig.other[i]]);
        }
    }
    h.hash(TAG_PK, &flat)
}

// --------------------------------------------------------------------------
// Merkle tree (sparse: unused leaves are 0)
// --------------------------------------------------------------------------

#[derive(Clone)]
pub struct MerkleTree<F: PrimeField> {
    pub depth: usize,
    levels: Vec<Vec<F>>, // levels[0] = leaves (populated prefix only)
    zero: Vec<F>,        // zero[l] = root of an empty subtree of height l
}

impl<F: PrimeField + Absorb> MerkleTree<F> {
    pub fn new(h: &Hasher<F>, depth: usize, leaves: Vec<F>) -> Self {
        assert!(leaves.len() <= 1usize << depth, "too many leaves");
        let mut zero = vec![F::zero()];
        for l in 0..depth {
            zero.push(h.node(zero[l], zero[l]));
        }
        let mut levels = vec![leaves];
        for l in 0..depth {
            let cur = &levels[l];
            let next: Vec<F> = (0..cur.len().div_ceil(2))
                .map(|i| h.node(cur[2 * i], *cur.get(2 * i + 1).unwrap_or(&zero[l])))
                .collect();
            levels.push(next);
        }
        MerkleTree { depth, levels, zero }
    }

    pub fn root(&self) -> F {
        *self.levels[self.depth].first().unwrap_or(&self.zero[self.depth])
    }

    pub fn path(&self, idx: usize) -> Vec<F> {
        (0..self.depth)
            .map(|l| *self.levels[l].get((idx >> l) ^ 1).unwrap_or(&self.zero[l]))
            .collect()
    }
}

pub fn merkle_root_from_path<F: PrimeField + Absorb>(h: &Hasher<F>, leaf: F, idx: usize, path: &[F]) -> F {
    path.iter().enumerate().fold(leaf, |cur, (l, sib)| {
        if (idx >> l) & 1 == 1 { h.node(*sib, cur) } else { h.node(cur, *sib) }
    })
}

// --------------------------------------------------------------------------
// Epoch key: XMSS-style subtree of Lamport keys (stateful)
// --------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DeviceSig<F: PrimeField> {
    /// Leaf (one-time key) inside the epoch subtree.
    pub leaf: usize,
    pub ots: OtsSig<F>,
    /// Authentication path inside the epoch subtree.
    pub path: Vec<F>,
}

/// One epoch subtree: 2^depth one-time keys under one root.
pub struct EpochKey<F: PrimeField> {
    seed: [u8; 32],
    tree: MerkleTree<F>,
    next: usize,
}

impl<F: PrimeField + Absorb> EpochKey<F> {
    pub fn generate(h: &Hasher<F>, seed: [u8; 32], depth: usize) -> Self {
        let leaves = (0..1u64 << depth).map(|i| ots_keygen(h, &seed, i).pk_hash).collect();
        EpochKey { seed, tree: MerkleTree::new(h, depth, leaves), next: 0 }
    }

    /// The epoch root (what the registry stores).
    pub fn public(&self) -> F {
        self.tree.root()
    }

    pub fn remaining(&self) -> usize {
        (1usize << self.tree.depth) - self.next
    }

    /// Sign one message with the next unused leaf. Reusing a leaf would
    /// break security, so the state only moves forward.
    pub fn sign(&mut self, h: &Hasher<F>, m: &F) -> DeviceSig<F> {
        let leaf = self.next;
        assert!(leaf < 1 << self.tree.depth, "epoch key exhausted");
        self.next += 1;
        let key = ots_keygen(h, &self.seed, leaf as u64);
        DeviceSig { leaf, ots: ots_sign(&key, m), path: self.tree.path(leaf) }
    }
}

/// Verify a device signature against an epoch root.
pub fn verify_device_sig<F: PrimeField + Absorb>(h: &Hasher<F>, epoch_root: F, m: &F, sig: &DeviceSig<F>) -> bool {
    let leaf = ots_pk_hash(h, m, &sig.ots);
    merkle_root_from_path(h, leaf, sig.leaf, &sig.path) == epoch_root
}

/// A device's request to add a new epoch root to the registry.
#[derive(Clone, Debug)]
pub struct EpochCert<F: PrimeField> {
    pub epoch: u64,
    pub root: F,
    /// Device ML-DSA-65 signature on (root, epoch).
    pub sig: Vec<u8>,
}

pub fn epoch_msg<F: PrimeField>(root: &F, epoch: u64) -> Vec<u8> {
    let mut m = field_bytes(root);
    m.extend(epoch.to_be_bytes());
    m
}

/// A recording device: long-term ML-DSA-65 identity (certified by the
/// manufacturer) plus the current epoch subtree.
pub struct Device<F: PrimeField> {
    mldsa: MlDsaSk,
    master: [u8; 32],
    pub epoch_depth: usize,
    epoch: u64,
    current: Option<EpochKey<F>>,
    /// Manufacturer ML-DSA-65 certificate on this device's ML-DSA key.
    pub cert: Vec<u8>,
}

impl<F: PrimeField + Absorb> Device<F> {
    pub fn manufacture(master: [u8; 32], mldsa_seed: [u8; 32], epoch_depth: usize, manufacturer: &MlDsaSk) -> Self {
        let mldsa = mldsa_from_seed(mldsa_seed);
        let cert = mldsa_sign(manufacturer, &mldsa_vk(&mldsa).encode(), CERT_CTX);
        Device { mldsa, master, epoch_depth, epoch: 0, current: None, cert }
    }

    pub fn vk_bytes(&self) -> Vec<u8> {
        mldsa_vk(&self.mldsa).encode().to_vec()
    }

    /// Budget key k_D (derived from the device master secret) and its tag.
    pub fn budget_key(&self, h: &Hasher<F>) -> (F, F) {
        use sha2::{Digest, Sha256};
        let d: [u8; 32] = Sha256::new().chain_update(b"zkmob/budget-key").chain_update(self.master).finalize().into();
        let k = F::from_le_bytes_mod_order(&d);
        (k, h.hash(TAG_DEVKEY, &[k]))
    }

    /// ML-DSA signature on the budget tag, for one-time registration.
    pub fn sign_budget_tag(&self, tag: &F) -> Vec<u8> {
        mldsa_sign(&self.mldsa, &field_bytes(tag), BUDGET_CTX)
    }

    /// Generate the next epoch subtree (seed = SHA-256(master || epoch)) and
    /// sign its root for the registry.
    pub fn new_epoch(&mut self, h: &Hasher<F>) -> EpochCert<F> {
        use sha2::{Digest, Sha256};
        self.epoch += 1;
        let seed: [u8; 32] = Sha256::new()
            .chain_update(b"zkmob/epoch-seed/v1")
            .chain_update(self.master)
            .chain_update(self.epoch.to_be_bytes())
            .finalize()
            .into();
        let key = EpochKey::generate(h, seed, self.epoch_depth);
        let root = key.public();
        self.current = Some(key);
        EpochCert { epoch: self.epoch, root, sig: mldsa_sign(&self.mldsa, &epoch_msg(&root, self.epoch), EPOCH_CTX) }
    }

    /// One-time keys left in the current epoch (0 = register a new epoch).
    pub fn remaining(&self) -> usize {
        self.current.as_ref().map_or(0, |k| k.remaining())
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sign a trace commitment with the next one-time key of the epoch.
    pub fn sign(&mut self, h: &Hasher<F>, m: &F) -> Result<DeviceSig<F>, String> {
        match self.current.as_mut() {
            Some(k) if k.remaining() > 0 => Ok(k.sign(h, m)),
            _ => Err("no one-time keys left: start and register a new epoch".into()),
        }
    }
}

// --------------------------------------------------------------------------
// ML-DSA helpers and the registry
// --------------------------------------------------------------------------

pub type MlDsaSk = ml_dsa::SigningKey<ml_dsa::MlDsa65>;
pub type MlDsaVk = ml_dsa::VerifyingKey<ml_dsa::MlDsa65>;

pub fn mldsa_from_seed(seed: [u8; 32]) -> MlDsaSk {
    MlDsaSk::from_seed(&seed.into())
}

pub fn mldsa_vk(sk: &MlDsaSk) -> MlDsaVk {
    sk.expanded_key().verifying_key()
}

pub fn mldsa_vk_decode(bytes: &[u8]) -> Option<MlDsaVk> {
    ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(bytes).ok().map(|e| MlDsaVk::decode(&e))
}

pub fn mldsa_sign(sk: &MlDsaSk, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    sk.expanded_key().sign_deterministic(msg, ctx).expect("ML-DSA sign").encode().to_vec()
}

pub fn mldsa_verify(vk: &MlDsaVk, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(sig) else { return false };
    match ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&enc) {
        Some(s) => vk.verify_with_context(msg, ctx, &s),
        None => false,
    }
}

struct Enrolled {
    vk: MlDsaVk,
    last_epoch: u64,
    budget_tag: Option<Vec<u8>>,
}

/// Public registry of epoch roots. Devices enroll once (manufacturer
/// certificate on their ML-DSA key); each new epoch root must carry that
/// device's ML-DSA signature and a strictly increasing epoch number. The
/// registry learns which device owns which epoch root, but proofs never
/// reveal which root they use. The Merkle root R is what verifiers check.
pub struct Registry<F: PrimeField> {
    pub depth: usize,
    leaves: Vec<F>,
    tree: MerkleTree<F>,
    devices: Vec<Enrolled>,
}

impl<F: PrimeField + Absorb> Registry<F> {
    pub fn new(h: &Hasher<F>, depth: usize) -> Self {
        Registry { depth, leaves: Vec::new(), tree: MerkleTree::new(h, depth, Vec::new()), devices: Vec::new() }
    }

    /// Enroll a device ML-DSA key certified by the manufacturer. Returns the
    /// device id.
    pub fn enroll(&mut self, device_vk: &[u8], cert: &[u8], manufacturer: &MlDsaVk) -> Result<usize, String> {
        if !mldsa_verify(manufacturer, device_vk, CERT_CTX, cert) {
            return Err("invalid manufacturer certificate".into());
        }
        let vk = mldsa_vk_decode(device_vk).ok_or("malformed device key")?;
        self.devices.push(Enrolled { vk, last_epoch: 0, budget_tag: None });
        Ok(self.devices.len() - 1)
    }

    /// Register device `id`'s budget tag once, signed with its ML-DSA key. A
    /// second, different tag would give the device a fresh budget, so it is
    /// rejected.
    pub fn register_budget_tag(&mut self, id: usize, tag: &F, sig: &[u8]) -> Result<(), String> {
        let dev = self.devices.get_mut(id).ok_or("unknown device")?;
        let t = field_bytes(tag);
        if !mldsa_verify(&dev.vk, &t, BUDGET_CTX, sig) { return Err("invalid budget-tag signature".into()); }
        match &dev.budget_tag {
            Some(old) if *old != t => Err("budget tag already registered".into()),
            _ => { dev.budget_tag = Some(t); Ok(()) }
        }
    }

    /// Add an epoch root of enrolled device `id`. Returns its leaf index.
    pub fn register_epoch(&mut self, h: &Hasher<F>, id: usize, ec: &EpochCert<F>) -> Result<usize, String> {
        let dev = self.devices.get_mut(id).ok_or("unknown device")?;
        if !mldsa_verify(&dev.vk, &epoch_msg(&ec.root, ec.epoch), EPOCH_CTX, &ec.sig) {
            return Err("invalid epoch signature".into());
        }
        if ec.epoch <= dev.last_epoch {
            return Err("epoch replayed or out of order".into());
        }
        dev.last_epoch = ec.epoch;
        // With a registered budget tag the leaf is H(E || K_D); devices
        // without one keep bare epoch roots (the N4 baseline circuits).
        let leaf = match &dev.budget_tag {
            Some(t) => h.hash(TAG_REGLEAF, &[ec.root, F::from_be_bytes_mod_order(t)]),
            None => ec.root,
        };
        self.leaves.push(leaf);
        self.tree = MerkleTree::new(h, self.depth, self.leaves.clone());
        Ok(self.leaves.len() - 1)
    }

    pub fn root(&self) -> F {
        self.tree.root()
    }

    pub fn path(&self, idx: usize) -> Vec<F> {
        self.tree.path(idx)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

// --------------------------------------------------------------------------
// Gadgets
// --------------------------------------------------------------------------

/// In-circuit Lamport verification: returns the one-time public-key hash
/// for message `m` (strictly decomposed into MODULUS_BIT_SIZE bits).
/// Cost: bit decomposition, one Poseidon per bit, 2 selects per bit, and
/// the compression of 2 * 254 public values.
pub fn ots_pk_hash_gadget<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    m: &FpVar<F>,
    reveal: &[FpVar<F>],
    other: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let bits = m.to_bits_le()?;
    let nbits = F::MODULUS_BIT_SIZE as usize;
    assert!(reveal.len() == nbits && other.len() == nbits);
    let mut flat = Vec::with_capacity(2 * nbits);
    for i in 0..nbits {
        let hv = hash_gadget(cs.clone(), cfg, TAG_OTS, &[reveal[i].clone()])?;
        let p0 = FpVar::conditionally_select(&bits[i], &other[i], &hv)?;
        let p1 = FpVar::conditionally_select(&bits[i], &hv, &other[i])?;
        flat.extend([p0, p1]);
    }
    hash_gadget(cs, cfg, TAG_PK, &flat)
}

/// Merkle root from a leaf, its index bits (little-endian) and siblings.
pub fn merkle_root_gadget<F: PrimeField + Absorb>(
    cs: ConstraintSystemRef<F>,
    cfg: &PoseidonConfig<F>,
    leaf: FpVar<F>,
    idx_bits: &[Boolean<F>],
    path: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut cur = leaf;
    for (b, sib) in idx_bits.iter().zip(path) {
        let l = FpVar::conditionally_select(b, sib, &cur)?;
        let r = FpVar::conditionally_select(b, &cur, sib)?;
        cur = hash_gadget(cs.clone(), cfg, TAG_NODE, &[l, r])?;
    }
    Ok(cur)
}

/// Allocate `idx` as `depth` little-endian witness bits.
pub fn alloc_index_bits<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    idx: usize,
    depth: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    (0..depth).map(|l| Boolean::new_witness(cs.clone(), || Ok((idx >> l) & 1 == 1))).collect()
}
