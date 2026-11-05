//! Verifier side of a presentation (paper, Fig. 1 step 8).
//!
//! A receipt proves the relation for the statement in its journal; the
//! verifier must still check that this statement is the one it asked for:
//! its own identity V, the current registry root R, the system-wide budget B,
//! the current period, and the policy it sent. It then accepts the outcome
//! only if the nullifier is new, which stops a replayed receipt or a reused
//! slot from being counted twice.
//!
//! Only succinct STARK receipts are accepted (paper, Sec. IV-E). A Groth16
//! receipt for the same image verifies under `Receipt::verify`, but its
//! soundness rests on BN254 pairings, which are not post-quantum; composite
//! receipts reveal the segment count, so they leak execution length; fake
//! receipts verify whenever `RISC0_DEV_MODE` is set. Verification therefore
//! checks the receipt kind first and then runs with dev mode explicitly off,
//! whatever the environment says. Deployments should also build with the
//! `production` feature, which compiles risc0's dev mode out entirely.
//!
//! The nullifier log prevents acceptance replay only. The bound on released
//! answers is enforced by the prover's wallet (`wallet.rs`; paper, A3), and a
//! malicious verifier can ignore these checks without harming the prover.
//! The log is in memory; a deployment persists it per period.

use std::collections::HashSet;
use std::fmt;

use methods::ZKMOB_GUEST_ID;
use risc0_zkvm::{InnerReceipt, Receipt, VerifierContext};
use zkmob_core::{Digest, Journal, Policy};

/// Why a presentation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// Not a succinct STARK receipt (Groth16, composite, fake or unknown kind).
    ReceiptKind(&'static str),
    /// The receipt does not verify against the guest image, or its journal
    /// does not decode.
    Receipt(String),
    /// Addressed to another verifier identity.
    Verifier,
    /// Proven against a registry root other than the current one.
    Root,
    /// Budget in the statement differs from the system-wide B.
    Budget { got: u32, want: u32 },
    /// Period in the statement is not the current one.
    Period { got: u32, want: u32 },
    /// Proves a policy other than the one requested.
    Policy,
    /// Nullifier already accepted: a replay or a reused slot.
    Replay,
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reject::ReceiptKind(k) => write!(f, "{k} receipt refused: only succinct STARK receipts are accepted"),
            Reject::Receipt(e) => write!(f, "receipt does not verify: {e}"),
            Reject::Verifier => write!(f, "statement names another verifier"),
            Reject::Root => write!(f, "statement uses a registry root other than the current one"),
            Reject::Budget { got, want } => write!(f, "budget {got} differs from the system budget {want}"),
            Reject::Period { got, want } => write!(f, "period {got} is not the current period {want}"),
            Reject::Policy => write!(f, "statement proves a policy other than the requested one"),
            Reject::Replay => write!(f, "nullifier already accepted"),
        }
    }
}

impl std::error::Error for Reject {}

/// Name of a receipt kind other than succinct, for error messages.
fn refused_kind(inner: &InnerReceipt) -> Option<&'static str> {
    match inner {
        InnerReceipt::Succinct(_) => None,
        InnerReceipt::Groth16(_) => Some("Groth16"),
        InnerReceipt::Composite(_) => Some("composite"),
        InnerReceipt::Fake(_) => Some("fake"),
        _ => Some("unknown"),
    }
}

/// Check the receipt kind, verify it against the guest image with dev mode
/// off, and decode its journal.
pub fn verified_journal(receipt: &Receipt) -> Result<Journal, Reject> {
    if let Some(kind) = refused_kind(&receipt.inner) {
        return Err(Reject::ReceiptKind(kind));
    }
    let ctx = VerifierContext::default().with_dev_mode(false);
    receipt.verify_with_context(&ctx, ZKMOB_GUEST_ID).map_err(|e| Reject::Receipt(e.to_string()))?;
    receipt.journal.decode().map_err(|e| Reject::Receipt(e.to_string()))
}

/// One verifier identity with its accepted nullifiers.
pub struct Verifier {
    id: Digest,
    budget: u32,
    reg_root: Digest,
    seen: HashSet<Digest>,
}

impl Verifier {
    /// `budget` is the system-wide B; `reg_root` the current registry root.
    pub fn new(id: Digest, budget: u32, reg_root: Digest) -> Self {
        Self { id, budget, reg_root, seen: HashSet::new() }
    }

    /// Adopt a new registry root (e.g. at a period boundary).
    pub fn set_root(&mut self, reg_root: Digest) {
        self.reg_root = reg_root;
    }

    /// Number of accepted presentations.
    pub fn accepted(&self) -> usize {
        self.seen.len()
    }

    /// Verify a receipt for `policy` in `current_period` and return the
    /// proven outcome. Nothing is recorded unless every check passes.
    pub fn accept(&mut self, receipt: &Receipt, policy: &Policy, current_period: u32) -> Result<bool, Reject> {
        let journal = verified_journal(receipt)?;
        self.accept_journal(&journal, policy, current_period)
    }

    /// The statement and nullifier checks, for a journal whose receipt has
    /// already been verified.
    pub fn accept_journal(&mut self, journal: &Journal, policy: &Policy, current_period: u32) -> Result<bool, Reject> {
        let st = &journal.statement;
        if st.verifier != self.id {
            return Err(Reject::Verifier);
        }
        if st.reg_root != self.reg_root {
            return Err(Reject::Root);
        }
        if st.budget != self.budget {
            return Err(Reject::Budget { got: st.budget, want: self.budget });
        }
        if st.period != current_period {
            return Err(Reject::Period { got: st.period, want: current_period });
        }
        if &st.policy != policy {
            return Err(Reject::Policy);
        }
        if !self.seen.insert(journal.nullifier) {
            return Err(Reject::Replay);
        }
        Ok(journal.outcome)
    }
}
