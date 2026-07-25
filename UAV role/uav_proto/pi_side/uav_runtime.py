"""Resident UAV activation and Algorithm 5/6 request processing."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import admission_control
import crypto_primitives as cp
import fuzzy_extractor
import merkle
import protocol_common as pc
import protocol_messages as pm
import revocation
import seeded_ml_dsa

UAV_CTX = b"uav-001"
SSI_TYPE = 0x01


class ProtocolAbort(ValueError):
    pass


class UAVProtocolService:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.in_dir = os.path.join(base_dir, "in")
        self.out_dir = os.path.join(base_dir, "out")
        self.params = pc.read_message(
            os.path.join(self.in_dir, "ta_public_params.json")
        )
        self.store = pc.read_message(
            os.path.join(self.out_dir, "uav_store_nv.json")
        )
        self.admission = admission_control.AdmissionController()
        current = int(time.time())
        persisted_time = self.store.get("last_trusted_time", 0)
        if current + self.params["freshness_tolerance_seconds"] < persisted_time:
            raise ProtocolAbort("trusted-time rollback detected at startup")
        self._last_wall = max(current, persisted_time)
        self._load_revocation()
        self._activate()
        self.store["last_trusted_time"] = self._last_wall
        pc.write_message(
            os.path.join(self.out_dir, "uav_store_nv.json"), self.store
        )

    def _load_revocation(self) -> None:
        update_path = os.path.join(self.in_dir, "ta_revocation_list.json")
        record = (
            pc.read_message(update_path)["rl_record"]
            if os.path.exists(update_path) else self.store["rl_record"]
        )
        self.rl = revocation.verify_record(
            record, self.params["pk_ta"],
            minimum_version=self.store.get("highest_rl_version", 0),
        )
        self.rl_record = record
        if self.rl["version"] > self.store.get("highest_rl_version", 0):
            self.store["highest_rl_version"] = self.rl["version"]
            self.store["rl_record"] = record

    def _trusted_now(self) -> int:
        now = int(time.time())
        if now + self.params["freshness_tolerance_seconds"] < self._last_wall:
            raise ProtocolAbort("trusted-time rollback detected")
        self._last_wall = max(self._last_wall, now)
        return now

    def _activate(self) -> None:
        now = self._trusted_now()
        candidates = []
        for stored in self.store["roots"]:
            body, signature = pm.decode_signed_record(
                stored["auth_record"], pm.TYPE_AUTH_RECORD
            )
            parsed = pm.decode_root_auth_body(body)
            ctx = parsed["flight_ctx"]
            if not ctx["start_time"] <= now <= ctx["end_time"]:
                continue
            with oqs.Signature(self.params["ml_dsa_alg"]) as verifier:
                if not verifier.verify(body, signature, self.params["pk_ta"]):
                    continue
            root_id = revocation.object_id(stored["auth_record"])
            key_identifier = revocation.key_id(parsed["pk_i"])
            revocation.assert_not_revoked(
                self.rl, root_id=root_id, key_id_value=key_identifier
            )
            candidates.append((ctx["k"], stored, parsed, root_id))
        if len(candidates) != 1:
            raise ProtocolAbort(
                f"expected exactly one currently valid root, found {len(candidates)}"
            )
        _, self.root_record, self.root, self.root_id = candidates[0]
        k_puf = fuzzy_extractor.rec_from_seed(
            self.store["c_seed"], self.store["helper_data"]
        )
        if k_puf is None:
            raise ProtocolAbort("PUF reconstruction failed during activation")
        _, s2 = pc.derive_purpose_secrets(k_puf, UAV_CTX)
        ctx_wire = self.root["flight_ctx_wire"]
        ctx = self.root["flight_ctx"]
        seed_k = pc.kdf_labeled(
            pc.TAG_MERKLE_ROOT, s2, self.root["root_nonce"], pc.u32(ctx["k"])
        )
        pids = []
        leaves = []
        for j in range(1, ctx["n"] + 1):
            x_kj = pc.kdf_labeled(pc.TAG_INTERVAL_SECRET, seed_k, pc.u32(j))
            pid = pc.hash_labeled(
                pc.TAG_RID, x_kj, pc.u32(j), self.root["root_nonce"], ctx_wire
            )[:16]
            pids.append(pid)
            leaves.append(
                merkle.leaf_hash(pid, j, self.root["root_nonce"], ctx_wire)
            )
        self.levels = merkle.build_tree(leaves)
        if merkle.root(self.levels) != self.root["mr_k"]:
            raise ProtocolAbort("locally regenerated root does not match AuthRec")
        self.pids = pids
        self.pid_to_j = {pid: index + 1 for index, pid in enumerate(pids)}

    def current_interval(self, timestamp: int | None = None) -> int:
        now = self._trusted_now() if timestamp is None else int(timestamp)
        ctx = self.root["flight_ctx"]
        j = 1 + (now - ctx["start_time"]) // ctx["delta_t"]
        if not 1 <= j <= ctx["n"]:
            raise ProtocolAbort("timestamp is outside the active root")
        return j

    def broadcast_record(self, timestamp: int | None = None) -> dict:
        now = self._trusted_now() if timestamp is None else int(timestamp)
        j = self.current_interval(now)
        pid = self.pids[j - 1]
        uas_id = bytes([SSI_TYPE]) + pid + b"\x00\x00\x00"
        return {"timestamp": now, "pid": pid.hex(), "uas_id": uas_id.hex()}

    def process_request(self, signed_wire: bytes) -> bytes:
        if len(signed_wire) > self.params["max_request_bytes"]:
            raise ProtocolAbort("request exceeds configured size limit")
        self.admission.pre_auth()
        req_wire, sigma_v = pm.decode_signed_request(signed_wire)
        request = pm.decode_verifier_request(req_wire)
        now = self._trusted_now()
        if abs(now - request["ts_v"]) > self.params["freshness_tolerance_seconds"]:
            raise ProtocolAbort("stale verifier timestamp")
        if request["revocation_version"] != self.rl["version"]:
            raise ProtocolAbort("revocation-list version mismatch")
        if request["requested_scope"] != self.root["flight_ctx"]["scope"]:
            raise ProtocolAbort("requested scope is not authorized by active root")

        cert_body, cert_sig = pm.decode_signed_record(
            request["cert_record"], pm.TYPE_CERT_RECORD
        )
        cert = pm.decode_cert_body(cert_body)
        with oqs.Signature(self.params["ml_dsa_alg"]) as verifier:
            if not verifier.verify(cert_body, cert_sig, self.params["pk_ta"]):
                raise ProtocolAbort("invalid verifier certificate")
            if not verifier.verify(req_wire, sigma_v, cert["pk_v"]):
                raise ProtocolAbort("invalid verifier request signature")
        if not cert["valid_from"] <= now <= cert["valid_until"]:
            raise ProtocolAbort("verifier certificate is outside validity")
        if cert["scope"] != request["requested_scope"]:
            raise ProtocolAbort("certificate scope mismatch")
        cert_id = revocation.object_id(request["cert_record"])
        revocation.assert_not_revoked(self.rl, cert_id=cert_id)

        req_id = pc.compute_req_id(req_wire)
        j = self.current_interval(request["ts_v"])
        if request["auth_ref"] != self.pids[j - 1]:
            raise ProtocolAbort("AuthRef does not match the timestamp-derived slot")
        self.admission.admit(
            cert_id, request["auth_ref"], request["n_v"], req_id
        )
        try:
            # Dispatch-time checks close queue-delay races.
            dispatch_now = self._trusted_now()
            if abs(dispatch_now - request["ts_v"]) > self.params["freshness_tolerance_seconds"]:
                raise ProtocolAbort("request expired while queued")
            revocation.assert_not_revoked(
                self.rl, cert_id=cert_id, root_id=self.root_id,
                key_id_value=revocation.key_id(self.root["pk_i"]),
            )
            path = merkle.auth_path(self.levels, j)
            with oqs.KeyEncapsulation(self.params["ml_kem_alg"]) as kem:
                ct, ss = kem.encap_secret(request["ek_v"])
            request_hash = cp.hash_bytes(req_wire)
            k_sess = pc.kdf_labeled(
                pc.TAG_RID_AUTH, ss, req_id, request_hash
            )[:16]

            k_puf = fuzzy_extractor.rec_from_seed(
                self.store["c_seed"], self.store["helper_data"]
            )
            if k_puf is None:
                raise ProtocolAbort("PUF reconstruction failed")
            s1, _ = pc.derive_purpose_secrets(k_puf, UAV_CTX)
            pk_i, sk_i = seeded_ml_dsa.seeded_keygen(
                self.params["ml_dsa_alg"], s1
            )
            if cp.hash_bytes(pk_i) != self.store["kc_i"] or pk_i != self.root["pk_i"]:
                raise ProtocolAbort("UAV key-confirmation check failed")
            ts_d = self._trusted_now()
            transcript = pm.encode_auth_transcript(
                req_id, request["auth_ref"], self.pids[j - 1], j,
                self.root_id, request["n_v"], request["ts_v"], ts_d, ct,
            )
            with oqs.Signature(self.params["ml_dsa_alg"], sk_i) as signer:
                sigma_d = signer.sign(transcript)
            payload = pm.encode_payload(
                request["auth_ref"], self.pids[j - 1], j, path,
                self.root_id, ts_d, sigma_d,
            )
            nonce = pc.compute_aead_nonce(req_id, ct)
            ad = pm.encode_aead_ad(req_id, ct, nonce, request_hash)
            ciphertext = cp.aead_encrypt(k_sess, nonce, ad, payload)
            return pm.encode_response_outer(req_id, ct, nonce, ciphertext)
        finally:
            self.admission.release()
