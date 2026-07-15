"""
merkle.py

Straightforward binary Merkle tree over Ascon-Hash leaves, no external
library needed for this part, it's a direct translation of the pair-and-
hash construction in Algorithm 1.
"""

from crypto_primitives import hash_bytes


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """
    Returns the full tree as a list of levels: levels[0] is the leaves,
    levels[-1] is [root]. Odd node counts duplicate the last node at that
    level (a common, simple convention; document this choice if you report
    exact proof sizes, since some Merkle-tree variants handle the odd case
    differently).
    """
    if not leaves:
        raise ValueError("build_tree requires at least one leaf")

    levels = [list(leaves)]
    current = leaves
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            nxt.append(hash_bytes(left + right))
        levels.append(nxt)
        current = nxt
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
