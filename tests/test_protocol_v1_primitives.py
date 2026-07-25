"""Dependency-light regression tests for the updated protocol primitives."""

import hashlib
import pathlib
import sys
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHARED = ROOT / "UAV role" / "uav_proto" / "shared"
sys.path.insert(0, str(SHARED))

# Protocol-common normally loads native Ascon. These encoding tests only need
# a deterministic 256-bit stand-in; this is test scaffolding, not a benchmark.
stub = types.ModuleType("crypto_primitives")
stub.hash_bytes = lambda value: hashlib.sha256(value).digest()
stub.kdf = lambda *parts: hashlib.sha256(b"".join(parts)).digest()
sys.modules.setdefault("crypto_primitives", stub)
tuple_stub = types.ModuleType("tuple_hash256")
tuple_stub.tuple_hash256 = lambda *parts: hashlib.sha384(
    b"".join(len(part).to_bytes(4, "big") + part for part in parts)
).digest()
sys.modules.setdefault("tuple_hash256", tuple_stub)

import admission_control
import bch950
import fuzzy_extractor
import merkle
import protocol_messages as pm


class ProtocolV1PrimitiveTests(unittest.TestCase):
    def test_shortened_bch_corrects_eight_errors(self):
        message = (1 << (bch950.SHORT_K - 1)) | 0x12345
        codeword = bch950.encode(message)
        noisy = codeword
        for position in (0, 4, 31, 88, 201, 477, 700, 949):
            noisy ^= 1 << position
        decoded = bch950.decode(noisy)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded[0], message)
        self.assertEqual(decoded[2], 8)

    def test_single_puf_helper_reconstructs_with_eight_selected_errors(self):
        enrollment = [[0] * 9 for _ in range(1023)]
        margins = [0.006 + index / 1_000_000 for index in range(1023)]
        key, helper = fuzzy_extractor.fe_gen(enrollment, margins)
        noisy = [[0] * 9 for _ in range(1023)]
        for index in helper["selection_indices"][:8]:
            noisy[index] = [1] * 9
        self.assertEqual(fuzzy_extractor.fe_rec(noisy, helper), key)
        self.assertEqual(helper["bch_n"], 950)
        self.assertEqual(helper["bch_k"], 870)

    def test_merkle_proof_binds_direction_index_and_depth(self):
        leaves = [bytes([index]) * 48 for index in range(8)]
        levels = merkle.build_tree(leaves)
        path = merkle.auth_path(levels, 3)
        root = merkle.root(levels)
        self.assertTrue(merkle.verify_path(leaves[2], 3, path, root, 8))
        self.assertFalse(merkle.verify_path(leaves[2], 4, path, root, 8))
        self.assertFalse(merkle.verify_path(leaves[2], 3, path[:-1], root, 8))
        with self.assertRaises(ValueError):
            merkle.build_tree(leaves[:7])

    def test_canonical_decoder_rejects_trailing_and_unknown_data(self):
        ctx = {
            "k": 1, "delta_t": 60, "n": 1024,
            "start_time": 100, "end_time": 61539,
            "region": "TEST-REGION", "scope": "test-deployment",
        }
        wire = pm.encode_flight_ctx(ctx)
        self.assertEqual(pm.decode_flight_ctx(wire), ctx)
        with self.assertRaises(ValueError):
            pm.decode_flight_ctx(wire + b"\x00")

    def test_replay_state_is_consumed_atomically(self):
        control = admission_control.AdmissionController(
            pair_gap_seconds=0, concurrent=1
        )
        control.pre_auth()
        values = (b"c" * 32, b"a" * 16, b"n" * 16, b"r" * 16)
        control.admit(*values)
        control.release()
        with self.assertRaises(admission_control.AdmissionError):
            control.admit(*values)


if __name__ == "__main__":
    unittest.main()
