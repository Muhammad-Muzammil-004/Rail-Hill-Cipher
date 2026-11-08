"""Custom cipher: Hill cipher followed by Rail Fence transposition.

Stage 1 (substitution): Hill cipher with a 3x3 key matrix derived from the key.
Stage 2 (transposition): Rail Fence zigzag with rail count derived from the key.

Key must be at least 10 characters long.
"""
from hill import key_to_matrix, encrypt as hill_encrypt, decrypt as hill_decrypt
from rail_fence import encrypt as rf_encrypt, decrypt as rf_decrypt


MIN_KEY_LEN = 10


def derive(key):
    if not isinstance(key, str) or len(key) < MIN_KEY_LEN:
        raise ValueError("Key must be at least %d characters long" % MIN_KEY_LEN)
    hill_matrix = key_to_matrix(key, 3)
    idx = 9 if len(key) > 9 else len(key) - 1
    ch = key[idx].upper()
    if 'A' <= ch <= 'Z':
        rails = (ord(ch) - ord('A')) % 7 + 2
    else:
        rails = (ord(ch) % 7) + 2
    if rails < 2:
        rails = 2
    return hill_matrix, rails


def encrypt(plaintext, key):
    hill_matrix, rails = derive(key)
    intermediate = hill_encrypt(plaintext, hill_matrix)
    ciphertext = rf_encrypt(intermediate, rails)
    return ciphertext


def decrypt(ciphertext, key):
    hill_matrix, rails = derive(key)
    intermediate = rf_decrypt(ciphertext, rails)
    plaintext = hill_decrypt(intermediate, hill_matrix)
    return plaintext.rstrip('X')


def encrypt_with_params(plaintext, hill_matrix, rails):
    intermediate = hill_encrypt(plaintext, hill_matrix)
    return rf_encrypt(intermediate, rails)


def decrypt_with_params(ciphertext, hill_matrix, rails):
    intermediate = rf_decrypt(ciphertext, rails)
    return hill_decrypt(intermediate, hill_matrix).rstrip('X')
