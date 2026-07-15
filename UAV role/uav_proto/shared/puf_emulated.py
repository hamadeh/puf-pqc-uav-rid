"""
puf_emulated.py

SOFTWARE-EMULATED PUF. This is NOT a real RO-PUF.

Simplified, for now, to exactly this: a random number, persisted per
challenge so the same challenge always returns the same value on this
machine. That's it, no attempt to model real PUF noise or bit-error
behaviour.

One property is kept even in this simplified version because the rest of
the protocol structurally depends on it: puf_response(C) must return the
SAME bytes every time it's called with the same challenge C on a given
device. Phase 3 (root activation) and Phase 4 (strong authentication)
both call this again, later, with the same challenge, to re-derive S1/S2
and regenerate keys/secrets that must match what enrollment produced. A
fresh random value on every call would silently break Merkle root
verification and key regeneration everywhere downstream of this module.

OPERATIONAL WARNING, hit this myself while testing: if you delete
.puf_store.json without also re-running Phase 2 enrollment from scratch,
any later Phase 3/4 script will get a DIFFERENT response for the same
challenge than the one enrollment used, and fuzzy_extractor.fe_rec() will
fail to reconstruct S1/S2 (it will return None). The failure looks like a
fuzzy-extractor bug but isn't one, it's a stale-state problem. If you ever
see FE.Rec failing unexpectedly, check whether .puf_store.json and
uav_store_nv.json actually came from the same enrollment run before
looking anywhere else.
"""

import hashlib
import json
import os
import secrets

_STORE_PATH = os.path.join(os.path.dirname(__file__), ".puf_store.json")


def _load_store() -> dict:
    if os.path.exists(_STORE_PATH):
        with open(_STORE_PATH, "r") as f:
            return json.load(f)
    return {}


def _save_store(store: dict) -> None:
    with open(_STORE_PATH, "w") as f:
        json.dump(store, f)


def puf_response(challenge: bytes, response_len_bytes: int = 128) -> bytes:
    """
    Emulated PUF(challenge) -> response: a random value, persisted per
    challenge so repeated calls with the same challenge (on this machine)
    return the same bytes.
    """
    store = _load_store()
    key = hashlib.sha256(challenge).hexdigest()

    if key not in store:
        store[key] = secrets.token_bytes(response_len_bytes).hex()
        _save_store(store)

    return bytes.fromhex(store[key])


def reset_store() -> None:
    """Erase all persisted emulated-PUF state (start a 'fresh device')."""
    if os.path.exists(_STORE_PATH):
        os.remove(_STORE_PATH)
