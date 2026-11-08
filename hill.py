"""Hill cipher (polygraphic substitution) over A-Z.

Uses an m x m key matrix and arithmetic modulo 26. Default block size m=3.
"""
import random
from typing import List

M = 26
DEFAULT_M_SIZE = 3


def _char_to_num(c):
    return ord(c.upper()) - ord('A')


def _num_to_char(n):
    return chr((n % M) + ord('A'))


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _modinv(a, m):
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def _det_mod(matrix, mod):
    n = len(matrix)
    if n == 1:
        return matrix[0][0] % mod
    if n == 2:
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % mod
    total = 0
    for j in range(n):
        minor = [row[:j] + row[j + 1:] for row in matrix[1:]]
        sign = -1 if j % 2 else 1
        total = (total + sign * matrix[0][j] * _det_mod(minor, mod)) % mod
    return total % mod


def _matrix_inv_mod(matrix, mod):
    n = len(matrix)
    det = _det_mod(matrix, mod)
    if _gcd(det % mod, mod) != 1:
        raise ValueError("matrix not invertible mod %d" % mod)
    det_inv = _modinv(det % mod, mod)
    cofactors = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [row[:j] + row[j + 1:] for k, row in enumerate(matrix) if k != i]
            c = _det_mod(minor, mod)
            cofactors[i][j] = ((-1) ** (i + j)) * c % mod
    adj = [[cofactors[j][i] % mod for j in range(n)] for i in range(n)]
    return [[(det_inv * adj[i][j]) % mod for j in range(n)] for i in range(n)]


def _mat_vec_mul(Mmat, vec, mod):
    n = len(Mmat)
    res = [0] * n
    for i in range(n):
        s = 0
        for j in range(n):
            s += Mmat[i][j] * vec[j]
        res[i] = s % mod
    return res


def key_to_matrix(key, size=3):
    letters = [c for c in key.upper() if 'A' <= c <= 'Z']
    needed = size * size
    if len(letters) < needed:
        letters = letters + ['A'] * (needed - len(letters))
    vals = [_char_to_num(c) for c in letters[:needed]]
    mat = [vals[i * size:(i + 1) * size] for i in range(size)]
    # try original
    try:
        _matrix_inv_mod(mat, M)
        return mat
    except ValueError:
        pass
    # deterministic random search
    import random
    rng = random.Random()
    rng.seed(sum((i + 1) * ord(c) for i, c in enumerate(key)) + len(key) * 97)
    for _ in range(10000):
        # perturb a few cells
        i = rng.randrange(size)
        j = rng.randrange(size)
        mat[i][j] = (mat[i][j] + rng.randrange(1, 26)) % M
        try:
            _matrix_inv_mod(mat, M)
            return [row[:] for row in mat]
        except ValueError:
            continue
    # fallback: fully random matrices
    for _ in range(10000):
        mat = [[rng.randrange(M) for _ in range(size)] for _ in range(size)]
        try:
            _matrix_inv_mod(mat, M)
            return mat
        except ValueError:
            continue
    raise RuntimeError("could not build invertible matrix from key")


def matrix_to_key(mat):
    return "".join(_num_to_char(v) for row in mat for v in row)


def encrypt(plaintext, key_matrix):
    size = len(key_matrix)
    letters = [c for c in plaintext.upper() if 'A' <= c <= 'Z']
    # pad
    while len(letters) % size != 0:
        letters.append('X')
    out = []
    for i in range(0, len(letters), size):
        block = letters[i:i + size]
        vec = [_char_to_num(c) for c in block]
        enc = _mat_vec_mul(key_matrix, vec, M)
        out.extend(_num_to_char(x) for x in enc)
    return "".join(out)


def decrypt(ciphertext, key_matrix):
    size = len(key_matrix)
    inv = _matrix_inv_mod(key_matrix, M)
    letters = [c for c in ciphertext.upper() if 'A' <= c <= 'Z']
    # pad if needed
    while len(letters) % size != 0:
        letters.append('X')
    out = []
    for i in range(0, len(letters), size):
        block = letters[i:i + size]
        vec = [_char_to_num(c) for c in block]
        dec = _mat_vec_mul(inv, vec, M)
        out.extend(_num_to_char(x) for x in dec)
    return "".join(out)
