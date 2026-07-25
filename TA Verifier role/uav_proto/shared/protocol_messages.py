"""Strict canonical binary objects for protocol version 1."""

import struct

import protocol_common as pc

MAGIC = b"URID"
MAX_OBJECT_BYTES = pc.MAX_REQUEST_BYTES

TYPE_FLIGHT_CTX = 1
TYPE_ROOT_REQUEST = 2
TYPE_ROOT_AUTH_BODY = 3
TYPE_AUTH_RECORD = 4
TYPE_CERT_REQUEST = 5
TYPE_CERT_BODY = 6
TYPE_CERT_RECORD = 7
TYPE_REVOCATION_BODY = 8
TYPE_REVOCATION_RECORD = 9
TYPE_VERIFIER_REQUEST = 10
TYPE_SIGNED_REQUEST = 11
TYPE_AUTH_TRANSCRIPT = 12
TYPE_PAYLOAD = 13
TYPE_AEAD_AD = 14
TYPE_RESPONSE_OUTER = 15

ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_CIPHERTEXT_BYTES = 1088
HASH256_BYTES = 32
HASH384_BYTES = 48
NONCE_BYTES = 16

_HEADER = struct.Struct("!4sBBH")
_FIELD = struct.Struct("!HI")


def _encode(object_type: int, fields: list[tuple[int, bytes]]) -> bytes:
    if any(not isinstance(value, bytes) for _, value in fields):
        raise TypeError("canonical fields must be bytes")
    identifiers = [identifier for identifier, _ in fields]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
        raise ValueError("canonical fields must be unique and ordered")
    output = bytearray(_HEADER.pack(MAGIC, pc.PROTOCOL_VERSION, object_type, len(fields)))
    for identifier, value in fields:
        output.extend(_FIELD.pack(identifier, len(value)))
        output.extend(value)
    if len(output) > MAX_OBJECT_BYTES:
        raise ValueError("canonical object exceeds configured maximum")
    return bytes(output)


def _decode(data: bytes, object_type: int,
            schema: dict[int, tuple[int, int]]) -> dict[int, bytes]:
    if not isinstance(data, bytes) or len(data) < _HEADER.size:
        raise ValueError("truncated canonical object")
    if len(data) > MAX_OBJECT_BYTES:
        raise ValueError("canonical object exceeds configured maximum")
    magic, version, actual_type, count = _HEADER.unpack_from(data)
    if magic != MAGIC or version != pc.PROTOCOL_VERSION or actual_type != object_type:
        raise ValueError("unsupported canonical object header")
    if count != len(schema):
        raise ValueError("missing or unknown critical fields")
    offset = _HEADER.size
    result = {}
    previous = 0
    for _ in range(count):
        if offset + _FIELD.size > len(data):
            raise ValueError("truncated field header")
        identifier, length = _FIELD.unpack_from(data, offset)
        offset += _FIELD.size
        if identifier <= previous or identifier not in schema:
            raise ValueError("duplicate, unordered, or unknown critical field")
        minimum, maximum = schema[identifier]
        if length < minimum or length > maximum or offset + length > len(data):
            raise ValueError("invalid canonical field length")
        result[identifier] = data[offset:offset + length]
        offset += length
        previous = identifier
    if offset != len(data):
        raise ValueError("trailing octets after canonical object")
    return result


def _text(value: str, maximum: int = 255) -> bytes:
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > maximum:
        raise ValueError("text field has invalid length")
    return encoded


def _decode_text(value: bytes) -> str:
    text = value.decode("utf-8")
    if not text:
        raise ValueError("empty text field")
    return text


def _number(value: bytes, width: int) -> int:
    if len(value) != width:
        raise ValueError("invalid integer width")
    return int.from_bytes(value, "big")


def encode_flight_ctx(ctx: dict) -> bytes:
    required = {"k", "delta_t", "n", "start_time", "end_time", "region", "scope"}
    if set(ctx) != required:
        raise ValueError("FlightCtx has missing or unknown fields")
    if ctx["end_time"] <= ctx["start_time"]:
        raise ValueError("FlightCtx end time must follow start time")
    return _encode(TYPE_FLIGHT_CTX, [
        (1, pc.u32(ctx["k"])), (2, pc.u32(ctx["delta_t"])),
        (3, pc.u32(ctx["n"])), (4, pc.u64(ctx["start_time"])),
        (5, pc.u64(ctx["end_time"])), (6, _text(ctx["region"])),
        (7, _text(ctx["scope"])),
    ])


def decode_flight_ctx(data: bytes) -> dict:
    fields = _decode(data, TYPE_FLIGHT_CTX, {
        1: (4, 4), 2: (4, 4), 3: (4, 4), 4: (8, 8), 5: (8, 8),
        6: (1, 255), 7: (1, 255),
    })
    ctx = {
        "k": _number(fields[1], 4), "delta_t": _number(fields[2], 4),
        "n": _number(fields[3], 4), "start_time": _number(fields[4], 8),
        "end_time": _number(fields[5], 8), "region": _decode_text(fields[6]),
        "scope": _decode_text(fields[7]),
    }
    if ctx["end_time"] <= ctx["start_time"]:
        raise ValueError("invalid FlightCtx validity interval")
    return ctx


def encode_root_request(pk_i: bytes, mr_k: bytes, root_nonce: bytes,
                        flight_ctx_wire: bytes, n_ta: bytes) -> bytes:
    return _encode(TYPE_ROOT_REQUEST, [
        (1, pk_i), (2, mr_k), (3, root_nonce), (4, flight_ctx_wire), (5, n_ta),
    ])


def decode_root_request(data: bytes) -> dict:
    f = _decode(data, TYPE_ROOT_REQUEST, {
        1: (ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES),
        2: (HASH384_BYTES, HASH384_BYTES), 3: (NONCE_BYTES, NONCE_BYTES),
        4: (1, 2048), 5: (NONCE_BYTES, NONCE_BYTES),
    })
    return {"pk_i": f[1], "mr_k": f[2], "root_nonce": f[3],
            "flight_ctx_wire": f[4], "n_ta": f[5],
            "flight_ctx": decode_flight_ctx(f[4])}


def encode_root_auth_body(pk_i: bytes, mr_k: bytes, root_nonce: bytes,
                          flight_ctx_wire: bytes) -> bytes:
    return _encode(TYPE_ROOT_AUTH_BODY, [
        (1, pk_i), (2, mr_k), (3, root_nonce), (4, flight_ctx_wire),
    ])


def decode_root_auth_body(data: bytes) -> dict:
    f = _decode(data, TYPE_ROOT_AUTH_BODY, {
        1: (ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES),
        2: (HASH384_BYTES, HASH384_BYTES), 3: (NONCE_BYTES, NONCE_BYTES),
        4: (1, 2048),
    })
    return {
        "pk_i": f[1], "mr_k": f[2], "root_nonce": f[3],
        "flight_ctx_wire": f[4], "flight_ctx": decode_flight_ctx(f[4]),
    }


def encode_signed_record(body: bytes, signature: bytes, object_type: int) -> bytes:
    return _encode(object_type, [(1, body), (2, signature)])


def decode_signed_record(data: bytes, object_type: int,
                         body_max: int = 8192) -> tuple[bytes, bytes]:
    f = _decode(data, object_type, {
        1: (1, body_max),
        2: (ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SIGNATURE_BYTES),
    })
    return f[1], f[2]


def encode_cert_request(verifier_id: str, organization: str, role: str,
                        scope: str, valid_from: int, valid_until: int,
                        pk_v: bytes, n_ta: bytes) -> bytes:
    return _encode(TYPE_CERT_REQUEST, [
        (1, _text(verifier_id)), (2, _text(organization)), (3, _text(role)),
        (4, _text(scope)), (5, pc.u64(valid_from)), (6, pc.u64(valid_until)),
        (7, pk_v), (8, n_ta),
    ])


def decode_cert_request(data: bytes) -> dict:
    f = _decode(data, TYPE_CERT_REQUEST, {
        1: (1, 255), 2: (1, 255), 3: (1, 255), 4: (1, 255),
        5: (8, 8), 6: (8, 8),
        7: (ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES),
        8: (NONCE_BYTES, NONCE_BYTES),
    })
    return {
        "verifier_id": _decode_text(f[1]), "organization": _decode_text(f[2]),
        "role": _decode_text(f[3]), "scope": _decode_text(f[4]),
        "valid_from": _number(f[5], 8), "valid_until": _number(f[6], 8),
        "pk_v": f[7], "n_ta": f[8],
    }


def encode_cert_body(verifier_id: str, organization: str, role: str,
                     scope: str, valid_from: int, valid_until: int,
                     pk_v: bytes) -> bytes:
    return _encode(TYPE_CERT_BODY, [
        (1, _text(verifier_id)), (2, _text(organization)), (3, _text(role)),
        (4, _text(scope)), (5, pc.u64(valid_from)), (6, pc.u64(valid_until)),
        (7, pk_v),
    ])


def decode_cert_body(data: bytes) -> dict:
    f = _decode(data, TYPE_CERT_BODY, {
        1: (1, 255), 2: (1, 255), 3: (1, 255), 4: (1, 255),
        5: (8, 8), 6: (8, 8),
        7: (ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES),
    })
    return {
        "verifier_id": _decode_text(f[1]), "organization": _decode_text(f[2]),
        "role": _decode_text(f[3]), "scope": _decode_text(f[4]),
        "valid_from": _number(f[5], 8), "valid_until": _number(f[6], 8),
        "pk_v": f[7],
    }


def _encode_id_list(values: list[bytes]) -> bytes:
    if values != sorted(values) or len(values) != len(set(values)):
        raise ValueError("revocation identifiers must be unique and ordered")
    if any(len(value) != HASH256_BYTES for value in values):
        raise ValueError("revocation identifiers must be 32 bytes")
    return pc.u16(len(values)) + b"".join(values)


def _decode_id_list(data: bytes) -> list[bytes]:
    if len(data) < 2:
        raise ValueError("truncated identifier list")
    count = _number(data[:2], 2)
    if len(data) != 2 + count * HASH256_BYTES:
        raise ValueError("invalid identifier-list length")
    values = [
        data[2 + index * HASH256_BYTES:2 + (index + 1) * HASH256_BYTES]
        for index in range(count)
    ]
    if values != sorted(values) or len(values) != len(set(values)):
        raise ValueError("noncanonical identifier list")
    return values


def encode_revocation_body(version: int, valid_from: int, valid_until: int,
                           cert_ids: list[bytes], root_ids: list[bytes],
                           key_ids: list[bytes]) -> bytes:
    return _encode(TYPE_REVOCATION_BODY, [
        (1, pc.u64(version)), (2, pc.u64(valid_from)), (3, pc.u64(valid_until)),
        (4, _encode_id_list(cert_ids)), (5, _encode_id_list(root_ids)),
        (6, _encode_id_list(key_ids)),
    ])


def decode_revocation_body(data: bytes) -> dict:
    f = _decode(data, TYPE_REVOCATION_BODY, {
        1: (8, 8), 2: (8, 8), 3: (8, 8),
        4: (2, 32770), 5: (2, 32770), 6: (2, 32770),
    })
    return {
        "version": _number(f[1], 8), "valid_from": _number(f[2], 8),
        "valid_until": _number(f[3], 8), "revoked_cert_ids": _decode_id_list(f[4]),
        "revoked_root_ids": _decode_id_list(f[5]),
        "revoked_key_ids": _decode_id_list(f[6]),
    }


def encode_verifier_request(cert_record: bytes, ek_v: bytes, auth_ref: bytes,
                            n_v: bytes, ts_v: int, requested_scope: str,
                            revocation_version: int) -> bytes:
    return _encode(TYPE_VERIFIER_REQUEST, [
        (1, cert_record), (2, ek_v), (3, auth_ref), (4, n_v),
        (5, pc.u64(ts_v)), (6, _text(requested_scope)),
        (7, pc.u64(revocation_version)),
    ])


def decode_verifier_request(data: bytes) -> dict:
    f = _decode(data, TYPE_VERIFIER_REQUEST, {
        1: (1, 8192), 2: (ML_KEM_768_PUBLIC_KEY_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES),
        3: (16, 16), 4: (16, 16), 5: (8, 8), 6: (1, 255), 7: (8, 8),
    })
    return {
        "cert_record": f[1], "ek_v": f[2], "auth_ref": f[3], "n_v": f[4],
        "ts_v": _number(f[5], 8), "requested_scope": _decode_text(f[6]),
        "revocation_version": _number(f[7], 8),
    }


def encode_signed_request(req_wire: bytes, signature: bytes) -> bytes:
    return encode_signed_record(req_wire, signature, TYPE_SIGNED_REQUEST)


def decode_signed_request(data: bytes) -> tuple[bytes, bytes]:
    return decode_signed_record(data, TYPE_SIGNED_REQUEST, 32768)


def encode_auth_transcript(req_id: bytes, auth_ref: bytes, pid: bytes, j: int,
                           root_id: bytes, n_v: bytes, ts_v: int, ts_d: int,
                           ct: bytes) -> bytes:
    return _encode(TYPE_AUTH_TRANSCRIPT, [
        (1, req_id), (2, auth_ref), (3, pid), (4, pc.u32(j)),
        (5, root_id), (6, n_v), (7, pc.u64(ts_v)), (8, pc.u64(ts_d)), (9, ct),
    ])


def encode_path(path: list[dict]) -> bytes:
    output = bytearray(pc.u16(len(path)))
    for entry in path:
        if set(entry) != {"direction", "sibling"}:
            raise ValueError("invalid Merkle-path entry")
        direction = entry["direction"]
        sibling = entry["sibling"]
        if direction not in (0, 1) or len(sibling) != HASH384_BYTES:
            raise ValueError("invalid Merkle-path direction or sibling")
        output.extend(bytes([direction]))
        output.extend(sibling)
    return bytes(output)


def decode_path(data: bytes) -> list[dict]:
    if len(data) < 2:
        raise ValueError("truncated Merkle path")
    count = _number(data[:2], 2)
    if len(data) != 2 + count * (1 + HASH384_BYTES):
        raise ValueError("invalid Merkle-path length")
    result = []
    offset = 2
    for _ in range(count):
        direction = data[offset]
        sibling = data[offset + 1:offset + 1 + HASH384_BYTES]
        if direction not in (0, 1):
            raise ValueError("invalid Merkle-path direction")
        result.append({"direction": direction, "sibling": sibling})
        offset += 1 + HASH384_BYTES
    return result


def encode_payload(auth_ref: bytes, pid: bytes, j: int, path: list[dict],
                   root_id: bytes, ts_d: int, sigma_d: bytes) -> bytes:
    return _encode(TYPE_PAYLOAD, [
        (1, auth_ref), (2, pid), (3, pc.u32(j)), (4, encode_path(path)),
        (5, root_id), (6, pc.u64(ts_d)), (7, sigma_d),
    ])


def decode_payload(data: bytes) -> dict:
    f = _decode(data, TYPE_PAYLOAD, {
        1: (16, 16), 2: (16, 16), 3: (4, 4), 4: (2, 2048),
        5: (32, 32), 6: (8, 8),
        7: (ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SIGNATURE_BYTES),
    })
    return {
        "auth_ref": f[1], "pid": f[2], "j": _number(f[3], 4),
        "auth_path": decode_path(f[4]), "root_id": f[5],
        "ts_d": _number(f[6], 8), "sigma_d": f[7],
    }


def encode_aead_ad(req_id: bytes, ct: bytes, nonce: bytes,
                   request_hash: bytes) -> bytes:
    return _encode(TYPE_AEAD_AD, [
        (1, req_id), (2, ct), (3, nonce), (4, request_hash),
    ])


def encode_response_outer(req_id: bytes, ct: bytes, nonce: bytes,
                          ciphertext: bytes) -> bytes:
    return _encode(TYPE_RESPONSE_OUTER, [
        (1, req_id), (2, ct), (3, nonce), (4, ciphertext),
    ])


def decode_response_outer(data: bytes) -> dict:
    f = _decode(data, TYPE_RESPONSE_OUTER, {
        1: (16, 16), 2: (ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_CIPHERTEXT_BYTES),
        3: (16, 16), 4: (16, 32768),
    })
    return {"req_id": f[1], "ct": f[2], "nonce": f[3], "ciphertext": f[4]}
