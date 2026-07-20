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
  Internal node: P_{l,r} = H384("node", l, r, P_{l-1,2r}, P_{l-1,2r+1})              Eq. (19)

using the 384-bit collision-sensitive TupleHash (tuple_hash256.py), not
the 256-bit general-purpose H256 crypto_primitives.hash_bytes()
provides -- the paper's own notation table distinguishes these as two
different primitives, and Section III.D is explicit that "the distinct
leaf and internal-node tags prevent cross-type substitution."
"""

from tuple_hash256 import tuple_hash256

_LEAF_MARKER = b"\x00"
_TAG_NODE = b"node"


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
    return tuple_hash256(_TAG_NODE, level.to_bytes(4, "big"), position.to_bytes(4, "big"), left, right)


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """
    Returns the full tree as a list of levels: levels[0] is the leaves
    (each already an L_kj from leaf_hash()), levels[-1] is [root]. Odd
    node counts duplicate the last node at that level (unchanged
    convention from before this rewrite; still worth documenting if you
    report exact proof sizes, since some Merkle-tree variants handle the
    odd case differently). Internal nodes are combined via node_hash(),
    which is where level/position get bound in.
    """
    if not leaves:
        raise ValueError("build_tree requires at least one leaf")

    levels = [list(leaves)]
    current = leaves
    level = 1
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            nxt.append(node_hash(level, i // 2, left, right))
        levels.append(nxt)
        current = nxt
        level += 1
    return levels


def root(levels: list[list[bytes]]) -> bytes:
    return levels[-1][0]


def auth_path(levels: list[list[bytes]], leaf_index: int) -> list[bytes]:
    """Authentication path (sibling hashes) for the leaf at leaf_index."""
    path = []
    idx = leaf_index
    for level in levels[:-1]:
        sibling_idx = idx ^ 1
        if sibling_idx >= len(level):
            sibling_idx = idx  # duplicated-last-node case
        path.append(level[sibling_idx])
        idx //= 2
    return path


def verify_path(leaf: bytes, leaf_index: int, path: list[bytes], expected_root: bytes) -> bool:
    """
    Recomputes the root from a leaf, its index, and its authentication
    path, using the same node_hash() level/position binding build_tree()
    used, and checks it against expected_root. This is the verifier
    side's counterpart to auth_path(); previously each verifier script
    reimplemented this walk locally with the old plain hash(left+right)
    logic, now centralized here so both sides can only ever agree or
    disagree about the SAME construction.
    """
    computed = leaf
    idx = leaf_index
    for level, sibling in enumerate(path, start=1):
        position = idx // 2
        if idx % 2 == 0:
            computed = node_hash(level, position, computed, sibling)
        else:
            computed = node_hash(level, position, sibling, computed)
        idx //= 2
    return computed == expected_root
