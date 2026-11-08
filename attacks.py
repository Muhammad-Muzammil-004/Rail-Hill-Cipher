"""Attack simulations for the custom Hill + Rail Fence cipher."""
import random
import string
import time
from hill import _gcd, _modinv, _matrix_inv_mod
import rail_fence
import custom_cipher
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074,
}


def _num(c):
    return ord(c.upper()) - ord('A')


def letter_counts(text):
    counts = {c: 0 for c in string.ascii_uppercase}
    for ch in text.upper():
        if ch in counts:
            counts[ch] += 1
    return counts


def letter_frequencies(text):
    counts = letter_counts(text)
    total = sum(counts.values()) or 1
    return {c: counts[c] / total * 100.0 for c in counts}


def chi_squared(text):
    counts = letter_counts(text)
    total = sum(counts.values()) or 1
    chi = 0.0
    for c in string.ascii_uppercase:
        expected = ENGLISH_FREQ[c] / 100.0 * total
        observed = counts[c]
        if expected > 0:
            chi += (observed - expected) ** 2 / expected
    return chi


def frequency_analysis(text):
    counts = letter_counts(text)
    freqs = letter_frequencies(text)
    total = sum(counts.values())
    sorted_freqs = sorted(freqs.items(), key=lambda kv: kv[1], reverse=True)
    return {
        'total_letters': total,
        'counts': counts,
        'frequencies': freqs,
        'chi_squared': chi_squared(text),
        'top5': sorted_freqs[:5],
    }

def _solve_mod_prime(A, b, p):
    m = len(A)
    n = len(A[0]) if m else 0
    M = [ [A[i][j] % p for j in range(n)] + [b[i] % p] for i in range(m) ]
    pivot_cols = []
    row = 0
    for col in range(n):
        piv = None
        for r in range(row, m):
            if M[r][col] % p != 0:
                piv = r
                break
        if piv is None:
            continue
        M[row], M[piv] = M[piv], M[row]
        inv = pow(M[row][col] % p, p - 2, p)
        M[row] = [(x * inv) % p for x in M[row]]
        for r in range(m):
            if r != row and M[r][col] % p != 0:
                factor = M[r][col] % p
                M[r] = [(M[r][k] - factor * M[row][k]) % p for k in range(n + 1)]
        pivot_cols.append(col)
        row += 1
        if row == m:
            break
    for r in range(row, m):
        if M[r][n] % p != 0:
            return None
    if len(pivot_cols) < n:
        return None
    x = [0] * n
    for idx, col in enumerate(pivot_cols):
        x[col] = M[idx][n] % p
    return x


def _solve_mod(A, b, mod=26):
    if not A:
        return None
    sol13 = _solve_mod_prime(A, b, 13)
    if sol13 is None:
        return None
    n = len(sol13)
    m = len(A)
    results = []
    for mask in range(1 << n):
        Kflat = [sol13[i] + 13 * ((mask >> i) & 1) for i in range(n)]
        ok = True
        for r in range(m):
            s = 0
            for j in range(n):
                s += A[r][j] * Kflat[j]
            if s % 26 != b[r] % 26:
                ok = False
                break
        if not ok:
            continue
        K = [Kflat[q * 3:(q + 1) * 3] for q in range(3)]
        try:
            _matrix_inv_mod(K, 26)
        except Exception:
            continue
        results.append(K)
    if not results:
        return None
    return results


def known_plaintext_attack(ciphertext, known_plaintext, max_rails=8):
    ct = "".join(c for c in ciphertext.upper() if c.isalpha())
    kp = "".join(c for c in known_plaintext.upper() if c.isalpha())
    n = len(ct)
    if n == 0 or not kp:
        return None
    L = min(len(kp), n)
    Lb = (L // 3) * 3
    if Lb < 9:
        return None

    best_overall = None
    for r in range(2, max_rails + 1):
        try:
            pi = rail_fence.permutation(n, r)
        except Exception:
            continue
        A_rows = []
        b_vals = []
        for b in range(Lb // 3):
            xs = [_num(kp[3 * b + j]) for j in range(3)]
            ys = [_num(ct[pi[3 * b + j]]) for j in range(3)]
            for q in range(3):
                row = [0] * 9
                for j in range(3):
                    row[q * 3 + j] = xs[j]
                A_rows.append(row)
                b_vals.append(ys[q])
        cands = _solve_mod(A_rows, b_vals, 26)
        if not cands:
            continue
        for K in cands:
            try:
                recovered = custom_cipher.decrypt_with_params(ct, K, r)
            except Exception:
                continue
            if recovered[:Lb].rstrip('X') != kp[:Lb].rstrip('X'):
                continue
            score = chi_squared(recovered)
            if best_overall is None or score < best_overall[0]:
                best_overall = (score, K, r, recovered)
    if best_overall is None:
        return None
    _, K, r, recovered = best_overall
    return K, r, recovered

def evaluate_kpa(num_trials=20, length=60, known_len=30, key_len=12):
    successes = 0
    times = []
    details = []
    for t in range(num_trials):
        pt = "".join(random.choice(string.ascii_uppercase) for _ in range(length))
        key = "".join(random.choice(string.ascii_uppercase) for _ in range(key_len))
        ct = custom_cipher.encrypt(pt, key)
        known = pt[:known_len]
        t0 = time.perf_counter()
        res = known_plaintext_attack(ct, known)
        dt = time.perf_counter() - t0
        times.append(dt)
        ok = False
        if res is not None:
            K, r, recovered = res
            if recovered[:length].rstrip('X') == pt.rstrip('X'):
                ok = True
        if ok:
            successes += 1
        details.append((t, ok, dt))
    import statistics
    return {
        'trials': num_trials,
        'successes': successes,
        'success_rate': successes / num_trials * 100.0,
        'avg_time': statistics.mean(times) if times else 0.0,
        'min_time': min(times) if times else 0.0,
        'max_time': max(times) if times else 0.0,
        'details': details,
    }


def benchmark(lengths=(100, 500, 1000, 5000), key='SECURITYKEY123'):
    results = []
    for L in lengths:
        pt = "A" * L
        t0 = time.perf_counter()
        ct = custom_cipher.encrypt(pt, key)
        t1 = time.perf_counter()
        _ = custom_cipher.decrypt(ct, key)
        t2 = time.perf_counter()
        enc_ct = (t1 - t0)
        dec_ct = (t2 - t1)
        shift = 3
        t0 = time.perf_counter()
        ct2 = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in pt)
        t1 = time.perf_counter()
        _ = "".join(chr((ord(c) - 65 - shift) % 26 + 65) for c in ct2)
        t2 = time.perf_counter()
        results.append({
            'length': L,
            'custom_enc': enc_ct,
            'custom_dec': dec_ct,
            'shift_enc': t1 - t0,
            'shift_dec': t2 - t1,
        })
    return results

