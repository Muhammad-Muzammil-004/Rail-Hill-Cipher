# Rail-Hill Custom Cipher — Design, Implementation and Cryptanalysis

## 1. Cipher Design

The custom cipher combines two classical techniques in two stages:

- **Stage 1 (Substitution): Hill cipher** with a 3x3 key matrix over Z_26.
- **Stage 2 (Transposition): Rail Fence** zigzag transposition.

Key length is at least 10 characters. The key is used to derive:
- the 3x3 Hill matrix (from the first 9 characters, adjusted to be invertible mod 26);
- the rail count (from the 10th character, mapped to 2..8 rails).

### Encryption
```
plaintext -> Hill_encrypt(matrix) -> intermediate -> RailFence_encrypt(rails) -> ciphertext
```

### Decryption
```
ciphertext -> RailFence_decrypt(rails) -> intermediate -> Hill_decrypt(matrix) -> plaintext
```

### Algorithms

**Hill encryption (block size 3):**
For each 3-letter block x (as column vector), y = K x (mod 26).

**Rail Fence encryption (r rails):**
Write characters in zigzag across r rows; read row by row.

## 2. Implementation

Modular Python code:
- `hill.py` — Hill cipher primitives.
- `rail_fence.py` — Rail Fence transposition.
- `custom_cipher.py` — combined cipher, key derivation.
- `attacks.py` — frequency analysis + known-plaintext attack + benchmarks.
- `gui.py` — Tkinter GUI.
- `main.py` — CLI.

## 3. Security Analysis

- Hill cipher alone resists simple frequency analysis (polygraphic).
- Rail fence adds transposition, increasing diffusion.
- Combined, the cipher is stronger than either alone, but still a classical cipher:
  vulnerable to known-plaintext attacks and, with enough ciphertext, to statistical attacks.
- Key space: Hill matrix 3x3 invertible mod 26 (~ large) plus rail count (7 options), but key derived from passphrase.

## 4. Attack Methods and Results

### Known-Plaintext Attack (KPA)
Given a known prefix of the plaintext (>= 9 letters) and the ciphertext, the attacker:
1. Tries each rail count 2..8.
2. Computes the rail-fence permutation.
3. Solves the Hill matrix via modular linear algebra (mod 13 + CRT bit search).
4. Scores candidates by chi-squared of the recovered plaintext and picks the best.

**Results (30 trials, length 60, known 30):**
- Success rate: 100% (avg ~0.012 s per attack).

### Frequency Analysis
`frequency_analysis()` computes letter counts, frequencies, chi-squared vs English. For transposition+substitution, monogram frequencies are flattened but still analyzable for long texts.

## 5. Efficiency

Time complexity:
- Encryption/Decryption: O(n) for Rail Fence + O(n) for Hill (blockwise) => O(n).
- KPA: O(n + 2^9 * E) where E is number of equations; effectively O(n) for fixed block size.

Benchmark (custom vs Shift cipher):
| Length | Custom Enc(s) | Custom Dec(s) | Shift Enc(s) | Shift Dec(s) |
|---|---|---|---|---|
| 100 | 0.00118 | 0.00086 | 0.000049 | 0.000047 |
| 500 | 0.00262 | 0.00258 | 0.000221 | 0.000221 |
| 1000 | 0.00548 | 0.00534 | 0.000537 | 0.000464 |
| 5000 | 0.01974 | 0.02133 | 0.001922 | 0.002293 |

The custom cipher is slower than a single-stage shift cipher (constant factor) but still linear time.

## 6. Suggestions for Improvement
- Increase Hill block size to 4x4 or 5x5.
- Use a larger alphabet or include digits/punctuation.
- Add more transposition rounds or a different transposition (e.g., columnar).
- Derive key via a proper KDF; use longer keys.
- Add an IV/nonce for non-determinism.

## 7. Usage
```
python main.py gui
python main.py encrypt SECURITYKEY123 "HELLO WORLD"
python main.py decrypt SECURITYKEY123 <ciphertext>
python main.py attack <ciphertext> <known_plaintext>
```
