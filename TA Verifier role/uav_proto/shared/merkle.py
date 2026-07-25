"""
merkle.py

Binary Merkle tree using the paper's actual leaf/internal-node
construction (Eq. 13-14, restated more fully as Eq. 19), not a generic
hash(left+right) tree. Previously this module used a single 256-bit
hash_bytes() call with no domain separation between a leaf and an
internal node and no binding of level/position into the hash; that
meant a leaf value and an internal-node value were structurally
interchangeable, and a proof could be replayed at the wrong tree
position without detection by the hash alone. The paper's construction
closes exactly that gap:

  Leaf:          L_kj    = H384(0x00, Enc(PID_kj, j, RootNonce_k, FlightCtx_k))     Eq. (13)
  Internal node: P_{l,r} = H384(0x01, l, r, P_{l-1,2r}, P_{l-1,2r+1})                Eq. (19)

using the 384-bit collision-sensitive TupleHash (tuple_hash256.py), not
the 256-bit general-purpose H256 crypto_primitives.hash_bytes()
provides -- the paper's own notation table distinguishes these as two
different primitives, and Section III.D is explicit that "the distinct
leaf and internal-node tags prevent cross-type substitution."
"""

from tuple_hash256 import tuple_hash256

_LEAF_MARKER = b"\x00"
_NODE_MARKER = b"\x01"


def leaf_hash(pid: bytes, j: int, root_nonce: bytes, flight_ctx_bytes: bytes) -> bytes:
    """
    L_kj, Eq. (13). flight_ctx_bytes must be the caller's canonical
    encoding of FlightCtx_k (protocol_common.canonical_json_bytes under
    this codebase's "keep JSON" convention), so both the UAV and the
    verifier hash the identical bytes for the identical logical context.
    """
    return tuple_hash256(_LEAF_MARKER, pid, j.to_bytes(4, "big"), root_nonce, flight_ctx_bytes)


def node_hash(level: int, position: int, left: bytes, right: bytes) -> bytes:
    """P_{l,r}, Eq. (19): ordered pair of children, level and position bound in."""
    return tuple_hash256(
        _NODE_MARKER, level.to_bytes(4, "big"),
        position.to_bytes(4, "big"), left, right,
    )


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """
    Returns the full tree as a list of levels: levels[0] is the leaves
    (each already an L_kj from leaf_hash()), levels[-1] is [root].
    Protocol roots require n to be a power of two, making every proof
    exactly log2(n) entries with no implicit odd-node convention.
    """
    if not leaves:
        raise ValueError("build_tree requires at least one leaf")
    if len(leaves) & (len(leaves) - 1):
        raise ValueError("protocol Merkle trees require a power-of-two leaf count")

    levels = [list(leaves)]
    current = leaves
    level = 1
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1]
            nxt.append(node_hash(level, i // 2, left, right))
        levels.append(nxt)
        current = nxt
        level += 1
    return levels


def root(levels: list[list[bytes]]) -> bytes:
    return levels[-1][0]


def auth_path(levels: list[list[bytes]], j: int) -> list[dict]:
    """Return the direction-bound path for one-based protocol interval j."""
    if not levels or j < 1 or j > len(levels[0]):
        raise ValueError("interval index is outside the Merkle tree")
    path = []
    idx = j - 1
    for level in levels[:-1]:
        sibling_idx = idx ^ 1
        path.append({"direction": idx & 1, "sibling": level[sibling_idx]})
        idx //= 2
    return path


def verify_path(leaf: bytes, j: int, path: list[dict],
                expected_root: bytes, n: int) -> bool:
    """
    Recomputes the root from a leaf, its index, and its authentication
    path, using the same node_hash() level/position binding build_tree()
    used, and checks it against expected_root. This is the verifier
    side's counterpart to auth_path(); previously each verifier script
    reimplemented this walk locally with the old plain hash(left+right)
    logic, now centralized here so both sides can only ever agree or
    disagree about the SAME construction.
    """
    if n < 1 or n & (n - 1) or j < 1 or j > n:
        return False
    if len(path) != n.bit_length() - 1:
        return False
    computed = leaf
    idx = j - 1
    for level, entry in enumerate(path, start=1):
        if not isinstance(entry, dict) or set(entry) != {"direction", "sibling"}:
            return False
        direction = entry["direction"]
        sibling = entry["sibling"]
        if direction not in (0, 1) or direction != (idx & 1):
            return False
        if not isinstance(sibling, bytes) or len(sibling) != len(leaf):
            return False
        position = idx // 2
        if direction == 0:
            computed = node_hash(level, position, computed, sibling)
        else:
            computed = node_hash(level, position, sibling, computed)
        idx //= 2
    return computed == expected_root
