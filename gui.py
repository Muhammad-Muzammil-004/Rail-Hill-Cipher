"""Tkinter GUI for the custom Rail-Hill cipher."""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import custom_cipher
import attacks
import time


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Rail-Hill Custom Cipher (CT-486)")
        self.geometry("900x700")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        self.tab_enc = ttk.Frame(nb)
        self.tab_attack = ttk.Frame(nb)
        self.tab_bench = ttk.Frame(nb)
        self.tab_freq = ttk.Frame(nb)
        nb.add(self.tab_enc, text="Encrypt / Decrypt")
        nb.add(self.tab_attack, text="Known-Plaintext Attack")
        nb.add(self.tab_bench, text="Benchmark")
        nb.add(self.tab_freq, text="Frequency Analysis")
        self._build_enc()
        self._build_attack()
        self._build_bench()
        self._build_freq()
    def _build_enc(self):
        f = self.tab_enc
        ttk.Label(f, text="Key (>=10 chars):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.key_var = tk.StringVar(value="SECURITYKEY123")
        ttk.Entry(f, textvariable=self.key_var, width=40).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(f, text="Plaintext:").grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        self.pt_box = scrolledtext.ScrolledText(f, width=90, height=10)
        self.pt_box.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(f, text="Ciphertext:").grid(row=2, column=0, sticky="nw", padx=5, pady=5)
        self.ct_box = scrolledtext.ScrolledText(f, width=90, height=10)
        self.ct_box.grid(row=2, column=1, padx=5, pady=5)
        btns = ttk.Frame(f)
        btns.grid(row=3, column=1, sticky="w", padx=5, pady=5)
        ttk.Button(btns, text="Encrypt", command=self.do_encrypt).pack(side="left", padx=5)
        ttk.Button(btns, text="Decrypt", command=self.do_decrypt).pack(side="left", padx=5)
        ttk.Button(btns, text="Clear", command=self.clear_enc).pack(side="left", padx=5)
        self.status = ttk.Label(f, text="")
        self.status.grid(row=4, column=1, sticky="w", padx=5, pady=5)

    def do_encrypt(self):
        key = self.key_var.get()
        pt = self.pt_box.get("1.0", "end").rstrip("\n")
        try:
            t0 = time.perf_counter()
            ct = custom_cipher.encrypt(pt, key)
            dt = time.perf_counter() - t0
            self.ct_box.delete("1.0", "end")
            self.ct_box.insert("1.0", ct)
            self.status.config(text="Encrypted in %.4f s" % dt)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_decrypt(self):
        key = self.key_var.get()
        ct = self.ct_box.get("1.0", "end").rstrip("\n")
        try:
            t0 = time.perf_counter()
            pt = custom_cipher.decrypt(ct, key)
            dt = time.perf_counter() - t0
            self.pt_box.delete("1.0", "end")
            self.pt_box.insert("1.0", pt)
            self.status.config(text="Decrypted in %.4f s" % dt)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clear_enc(self):
        self.pt_box.delete("1.0", "end")
        self.ct_box.delete("1.0", "end")
        self.status.config(text="")

    def _build_attack(self):
        f = self.tab_attack
        ttk.Label(f, text="Ciphertext:").grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.atk_ct = scrolledtext.ScrolledText(f, width=90, height=8)
        self.atk_ct.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(f, text="Known plaintext:").grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        self.atk_known = scrolledtext.ScrolledText(f, width=90, height=4)
        self.atk_known.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(f, text="Note: use letters A-Z only for attack.").grid(row=2, column=1, sticky="w", padx=5)
        ttk.Button(f, text="Run KPA", command=self.run_kpa).grid(row=3, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(f, text="Recovered plaintext:").grid(row=4, column=0, sticky="nw", padx=5, pady=5)
        self.atk_out = scrolledtext.ScrolledText(f, width=90, height=10)
        self.atk_out.grid(row=4, column=1, padx=5, pady=5)
        self.atk_status = ttk.Label(f, text="")
        self.atk_status.grid(row=5, column=1, sticky="w", padx=5, pady=5)

    def run_kpa(self):
        ct = self.atk_ct.get("1.0", "end").strip()
        known = self.atk_known.get("1.0", "end").strip()
        try:
            t0 = time.perf_counter()
            res = attacks.known_plaintext_attack(ct, known)
            dt = time.perf_counter() - t0
            if res is None:
                self.atk_status.config(text="Attack failed (%.4f s)" % dt)
                messagebox.showinfo("KPA", "Could not recover key.")
                return
            K, r, recovered = res
            self.atk_out.delete("1.0", "end")
            self.atk_out.insert("1.0", recovered)
            keymat = " ".join(str(row) for row in K)
            self.atk_status.config(text="Recovered rails=%d in %.4f s | matrix=%s" % (r, dt, keymat))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _build_bench(self):
        f = self.tab_bench
        ttk.Button(f, text="Run Benchmark", command=self.run_bench).pack(pady=10)
        self.bench_out = scrolledtext.ScrolledText(f, width=90, height=20)
        self.bench_out.pack(padx=10, pady=10)

    def run_bench(self):
        res = attacks.benchmark()
        lines = ["Length | Custom Enc(s) | Custom Dec(s) | Shift Enc(s) | Shift Dec(s)"]
        lines.append("-" * 70)
        for r in res:
            lines.append("%6d | %13.6f | %13.6f | %12.6f | %12.6f" % (
                r['length'], r['custom_enc'], r['custom_dec'], r['shift_enc'], r['shift_dec']))
        sr = attacks.evaluate_kpa(num_trials=10, length=60, known_len=30, key_len=12)
        lines.append("")
        lines.append("KPA success rate (10 trials): %.1f%% (avg %.4f s)" % (sr['success_rate'], sr['avg_time']))
        self.bench_out.delete("1.0", "end")
        self.bench_out.insert("1.0", "\n".join(lines))

    def _build_freq(self):
        f = self.tab_freq
        ttk.Label(f, text="Text:").pack(anchor="w", padx=5, pady=5)
        self.freq_in = scrolledtext.ScrolledText(f, width=90, height=8)
        self.freq_in.pack(padx=10, pady=5)
        ttk.Button(f, text="Analyze", command=self.run_freq).pack(pady=5)
        self.freq_out = scrolledtext.ScrolledText(f, width=90, height=20)
        self.freq_out.pack(padx=10, pady=5)

    def run_freq(self):
        text = self.freq_in.get("1.0", "end")
        info = attacks.frequency_analysis(text)
        lines = ["Total letters: %d" % info['total_letters']]
        lines.append("Chi-squared vs English: %.2f" % info['chi_squared'])
        lines.append("Top 5 by frequency:")
        for c, v in info['top5']:
            lines.append("  %s: %.2f%%" % (c, v))
        lines.append("All frequencies:")
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            lines.append("  %s: %6.2f%%  count=%d" % (c, info['frequencies'][c], info['counts'][c]))
        self.freq_out.delete("1.0", "end")
        self.freq_out.insert("1.0", "\n".join(lines))


if __name__ == "__main__":
    app = App()
    app.mainloop()

