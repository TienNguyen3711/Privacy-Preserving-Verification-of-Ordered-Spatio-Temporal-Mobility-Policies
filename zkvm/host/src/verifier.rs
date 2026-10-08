//! Verifier side of a presentation (paper, Fig. 1 step 8).
//!
//! A receipt proves the relation for the statement in its journal; the
//! verifier must still check that this statement is the one it asked for:
//! its own identity V, the current registry root R, the system-wide budget B,
//! the current period, and the policy it sent. It then accepts the outcome
//! only if the nullifier is new, which stops a replayed receipt or a reused
//! slot from being counted twice.
//!
//! The nullifier log prevents acceptance replay only. The bound on released
//! answers is enforced by the prover's wallet (`wallet.rs`; paper, A3), and a
//! malicious verifier can ignore these checks without harming the prover.
//! The log is in memory; a deployment persists it per period.

use std::collections::HashSet;
use std::fmt;

use methods::ZKMOB_GUEST_ID;
use risc0_zkvm::Receipt;
use zkmob_core::{Digest, Journal, Policy};

/// Why a presentation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
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
        receipt.verify(ZKMOB_GUEST_ID).map_err(|e| Reject::Receipt(e.to_string()))?;
        let journal: Journal = receipt.journal.decode().map_err(|e| Reject::Receipt(e.to_string()))?;
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
