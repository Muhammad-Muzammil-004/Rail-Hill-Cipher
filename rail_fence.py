"""Rail Fence (zigzag) transposition cipher.

Classical technique: transposition. The plaintext is written in a zigzag
pattern across `rails` rows and read off row by row.
"""
from typing import List


def _rail_pattern(n: int, rails: int) -> List[int]:
    """Return the row index for each position in a zigzag of length n."""
    if rails < 2:
        rails = 2
    pattern = []
    row = 0
    direction = 1
    for _ in range(n):
        pattern.append(row)
        row += direction
        if row == 0 or row == rails - 1:
            direction *= -1
    return pattern


def encrypt(plaintext: str, rails: int) -> str:
    """Encrypt plaintext using rail fence with given number of rails."""
    if rails < 2:
        rails = 2
    n = len(plaintext)
    if n == 0:
        return ""
    rows: List[List[str]] = [[] for _ in range(rails)]
    for ch, r in zip(plaintext, _rail_pattern(n, rails)):
        rows[r].append(ch)
    return "".join("".join(row) for row in rows)


def permutation(n, rails):
    """Return list pos_map where ciphertext[pos_map[i]] == plaintext[i]."""
    if rails < 2:
        rails = 2
    if n == 0:
        return []
    pattern = _rail_pattern(n, rails)
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1
    starts = [0] * rails
    acc = 0
    for r in range(rails):
        starts[r] = acc
        acc += counts[r]
    pos_map = [0] * n
    cur = list(starts)
    for i, r in enumerate(pattern):
        pos_map[i] = cur[r]
        cur[r] += 1
    return pos_map


def decrypt(ciphertext, rails):
    """Decrypt ciphertext produced by rail fence."""
    if rails < 2:
        rails = 2
    n = len(ciphertext)
    if n == 0:
        return ""
    pattern = _rail_pattern(n, rails)
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1
    rails_chars: List[List[str]] = []
    idx = 0
    for r in range(rails):
        rails_chars.append(list(ciphertext[idx:idx + counts[r]]))
        idx += counts[r]
    result = []
    pointers = [0] * rails
    for r in pattern:
        result.append(rails_chars[r][pointers[r]])
        pointers[r] += 1
    return "".join(result)
