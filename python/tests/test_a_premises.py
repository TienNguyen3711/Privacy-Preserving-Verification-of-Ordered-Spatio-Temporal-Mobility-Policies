"""Counterexamples explaining why A needs its operational/crypto premises.

These are executable finite-channel examples, NOT an implementation of the
required production wallet or a proof of adaptive cryptographic simulation.
"""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zkmob.disclosure import guessing_bound


def guessing(transcripts):
    """Uniform candidates, deterministic observations: one guess per leaf."""
    return len(set(transcripts)) / len(transcripts)


class APremises(unittest.TestCase):
    def test_accepted_count_does_not_bound_released_answers(self):
        # Two policies evaluated using one slot; verifier rejects the second
        # duplicate nullifier but has already read both public outcome bits.
        transcripts = [(t & 1, (t >> 1) & 1) for t in range(4)]
        self.assertEqual(guessing(transcripts), 1)
        self.assertGreater(guessing(transcripts), guessing_bound(1 / 4, 1))

    def test_reset_or_cap_increase_breaks_original_budget(self):
        # Resetting a RAM-only wallet, or changing B from 1 to 2, releases a
        # second independent bit. Authenticity of each individual proof helps
        # neither case: the lifetime disclosure count is the missing premise.
        for failure in ('reset', 'increase_cap'):
            with self.subTest(failure=failure):
                self.assertEqual(guessing([(t % 2, t // 2) for t in range(4)]), 1)
                self.assertEqual(guessing_bound(.25, 1), .5)

    def test_refusal_is_an_observation_even_without_answers(self):
        # A zero-answer system signals a predicate by two different statuses.
        self.assertEqual(guessing(['refuse', 'error']), 1)
        self.assertEqual(guessing_bound(.5, 0), .5)

    def test_hidden_prior_session_can_leak_through_exhaustion(self):
        # Current session sees no bits. Secret-dependent prior use determines
        # whether its first request is exhausted: that hidden history cannot
        # be omitted from the experiment/side information.
        self.assertGreater(guessing(['exhausted', 'available']), guessing_bound(.5, 0))

    def test_idempotent_retries_add_no_new_partition(self):
        once = [(t % 2,) for t in range(4)]
        retries = [(t % 2,) * 20 for t in range(4)]
        self.assertEqual(guessing(once), guessing(retries))
        self.assertEqual(guessing(retries), guessing_bound(.25, 1))

    def test_coalition_requires_sum_of_budgets(self):
        pooled = [(t % 2, t // 2) for t in range(4)]
        self.assertGreater(guessing(pooled), guessing_bound(.25, 1))
        self.assertEqual(guessing(pooled), guessing_bound(.25, 2))

    def test_deterministic_zkvm_fixture_nullifier_identifies_candidate(self):
        # Exact encoding from zkvm/{host,core}: setup's length-derived blind,
        # commit tag + raw u32 fixes, then nullifier tag + C + V + u32 slot.
        # All candidates have the SAME policy answer (e.g. visit a box
        # containing every point); only the public nullifier distinguishes.
        sha = lambda data: hashlib.sha256(data).digest()
        verifier = sha(b'verifier/insurer-A')
        candidates = [[(10 + t, 10, 0), (20 + t, 20, 10)] for t in range(4)]
        nullifiers = []
        for trace in candidates:
            blind = sha(b'blind' + struct.pack('<I', len(trace)))[:16]
            encoded = b''.join(struct.pack('<III', *p) for p in trace)
            commitment = sha(b'zkmob/commit' + blind + encoded)
            nullifiers.append(sha(b'zkmob/null' + commitment + verifier + struct.pack('<I', 0)))
        self.assertEqual(guessing([(True,)] * 4), .25)
        self.assertEqual(guessing(nullifiers), 1)
        self.assertGreater(guessing(nullifiers), guessing_bound(.25, 1))


if __name__ == '__main__':
    unittest.main()
