#!/usr/bin/env python3
"""
pw_analyzer_gui.py

Password Strength Analyzer — Tkinter GUI

Features:
- Real-time entropy estimate and strength label
- Policy checks and recommendations
- Optional "Sanitized Report" export (does NOT save the raw password)
- Small local blacklist (extendable via file)

Security notes:
- This script intentionally does NOT log or store raw passwords.
- If you add breach-checking (HaveIBeenPwned), use k-anonymity and never send full password.
"""

import math
import re
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# A very small example blacklist; replace/extend with a file for real use.
COMMON_WORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin", "welcome"
}

SYMBOLS = r"""!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

# -------------------------
# Analysis/Utility functions
# -------------------------
def char_space_size(pw: str) -> int:
    s = 0
    if re.search(r'[a-z]', pw): s += 26
    if re.search(r'[A-Z]', pw): s += 26
    if re.search(r'[0-9]', pw): s += 10
    if re.search(r'[' + re.escape(SYMBOLS) + r']', pw): s += 33
    return s if s > 0 else 1

def entropy_bits(pw: str) -> float:
    space = char_space_size(pw)
    # Protect against math domain errors if pw empty
    if not pw:
        return 0.0
    return len(pw) * math.log2(space)

def classify_entropy(bits: float) -> str:
    if bits < 28:
        return "Very weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Moderate"
    return "Strong"

def policy_checks(pw: str, min_len=8):
    issues = []
    if len(pw) < min_len:
        issues.append(f"Too short (min {min_len})")
    if not re.search(r'[a-z]', pw):
        issues.append("No lowercase letters")
    if not re.search(r'[A-Z]', pw):
        issues.append("No uppercase letters")
    if not re.search(r'[0-9]', pw):
        issues.append("No digits")
    if not re.search(r'[' + re.escape(SYMBOLS) + r']', pw):
        issues.append("No symbols")
    if re.search(r'(.)\1\1', pw):
        issues.append("Has repeated characters (e.g., 'aaa')")
    if pw.lower() in COMMON_WORDS:
        issues.append("Common password / on blacklist")
    return issues

def recommendations_from_issues(issues):
    recs = []
    if not issues:
        recs.append("Looks good. Consider using a passphrase for additional strength.")
    else:
        if any("Too short" in i for i in issues):
            recs.append("Increase length — length adds entropy faster than extra complexity.")
        if any("Common password" in i for i in issues):
            recs.append("Avoid common words/passwords. Use uncommon words or a passphrase.")
        if any("No uppercase" in i or "No lowercase" in i for i in issues):
            recs.append("Mix uppercase and lowercase letters (or use multiple words).")
        if any("No digits" in i for i in issues):
            recs.append("Add digits or use separators in a passphrase.")
        if any("No symbols" in i for i in issues):
            recs.append("Add symbols or punctuation to increase variety.")
        if any("repeated" in i.lower() for i in issues):
            recs.append("Avoid repeated characters or predictable sequences.")
    return recs

# -------------------------
# GUI
# -------------------------
class PWAnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Analyzer")
        self.geometry("640x420")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        pad = {"padx": 8, "pady": 6}

        # Input frame
        frm_in = ttk.LabelFrame(self, text="Password (local only, not stored)")
        frm_in.pack(fill="x", **pad,)
        self.pw_var = tk.StringVar()
        pw_entry = ttk.Entry(frm_in, textvariable=self.pw_var, show="*", font=("Segoe UI", 11))
        pw_entry.pack(fill="x", padx=10, pady=8)
        pw_entry.bind("<KeyRelease>", lambda e: self.update_analysis())

        # Show/hide checkbox
        self.show_var = tk.BooleanVar(value=False)
        cb = ttk.Checkbutton(frm_in, text="Show password", variable=self.show_var, command=lambda: self.toggle_show(pw_entry))
        cb.pack(anchor="w", padx=10, pady=(0,8))

        # Strength frame
        frm_str = ttk.Frame(self)
        frm_str.pack(fill="x", padx=12)
        ttk.Label(frm_str, text="Entropy (bits):").grid(row=0, column=0, sticky="w")
        self.entropy_lbl = ttk.Label(frm_str, text="0.00")
        self.entropy_lbl.grid(row=0, column=1, sticky="w", padx=(6,0))

        ttk.Label(frm_str, text="Strength:").grid(row=0, column=2, sticky="w", padx=(18,0))
        self.str_lbl = ttk.Label(frm_str, text="—")
        self.str_lbl.grid(row=0, column=3, sticky="w", padx=(6,0))

        # Progress bar for visual strength
        self.str_bar = ttk.Progressbar(frm_str, orient="horizontal", length=360, mode="determinate", maximum=100)
        self.str_bar.grid(row=1, column=0, columnspan=4, pady=(8,0), sticky="w")

        # Checks and recommendations
        frm_checks = ttk.LabelFrame(self, text="Policy checks & recommendations")
        frm_checks.pack(fill="both", expand=True, padx=12, pady=(8,0))
        self.checks_text = tk.Text(frm_checks, height=10, wrap="word", state="disabled", padx=8, pady=6)
        self.checks_text.pack(fill="both", expand=True)

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=12, pady=10)
        ttk.Button(btn_frame, text="Sanitized Report (export)", command=self.export_report).pack(side="left")
        ttk.Button(btn_frame, text="Example: Generate Passphrase", command=self.example_passphrase).pack(side="left", padx=(8,0))
        ttk.Button(btn_frame, text="About / Notes", command=self.show_about).pack(side="right")

        # Initial update
        self.update_analysis()

    def toggle_show(self, entry):
        if self.show_var.get():
            entry.config(show="")
        else:
            entry.config(show="*")

    def update_analysis(self):
        pw = self.pw_var.get()
        bits = entropy_bits(pw)
        label = classify_entropy(bits)
        issues = policy_checks(pw)
        recs = recommendations_from_issues(issues)

        # Update labels
        self.entropy_lbl.config(text=f"{bits:.2f}")
        self.str_lbl.config(text=label)

        # Update progress bar (map bits -> 0..100)
        # 0 bits -> 0; 60 bits -> 100 (cap)
        pct = min(100, (bits / 60) * 100 if bits > 0 else 0)
        self.str_bar['value'] = pct

        # Update checks text
        self.checks_text.config(state="normal")
        self.checks_text.delete("1.0", "end")
        if not pw:
            self.checks_text.insert("end", "No password entered. Try typing a password or use 'Generate Passphrase'.\n")
        else:
            self.checks_text.insert("end", f"Length: {len(pw)}\n")
            self.checks_text.insert("end", f"Entropy (bits): {bits:.2f}\n")
            self.checks_text.insert("end", f"Strength: {label}\n\n")
            self.checks_text.insert("end", "Policy checks:\n")
            if issues:
                for i in issues:
                    self.checks_text.insert("end", f" - {i}\n")
            else:
                self.checks_text.insert("end", " - All checks passed.\n")
            self.checks_text.insert("end", "\nRecommendations:\n")
            for r in recs:
                self.checks_text.insert("end", f" - {r}\n")

            self.checks_text.insert("end", "\nSecurity note: This GUI does not transmit or save your raw password.\n")
        self.checks_text.config(state="disabled")

    def export_report(self):
        # Export a sanitized report (no raw password)
        pw = self.pw_var.get()
        if not pw:
            messagebox.showinfo("Export", "No password entered; nothing to export.")
            return

        bits = entropy_bits(pw)
        label = classify_entropy(bits)
        issues = policy_checks(pw)

        rep = {
            "length": len(pw),
            "entropy_bits": round(bits, 2),
            "strength": label,
            "issues": issues,
            "recommendations": recommendations_from_issues(issues)
        }

        fpath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files","*.json"), ("Text files","*.txt")],
            title="Save sanitized report"
        )
        if not fpath:
            return
        try:
            with open(fpath, "w", encoding="utf-8") as fh:
                json.dump(rep, fh, indent=2)
            messagebox.showinfo("Export", f"Sanitized report saved to:\n{fpath}")
        except Exception as e:
            messagebox.showerror("Export error", f"Could not save file: {e}")

    def example_passphrase(self):
        # Small example generator: 4 random words from a built-in list.
        words = ["battery","staple","river","keyboard","orange","planet","window","coffee","guitar","museum","crystal","forest"]
        import random
        pw = "-".join(random.sample(words, 4))
        # Show in a popup; don't auto-populate main field (keeps UX explicit)
        answer = messagebox.askyesno("Generated Passphrase", f"Example passphrase:\n\n{pw}\n\nWould you like to copy it into the password field?")
        if answer:
            self.pw_var.set(pw)
            self.update_analysis()

    def show_about(self):
        messagebox.showinfo("About / Notes",
            "Password Strength Analyzer GUI\n\n"
            "This tool estimates entropy and gives policy suggestions.\n"
            "It does NOT store or transmit your raw password.\n\n"
            "For breach checking, integrate k-anonymity APIs (HIBP) responsibly."
        )

# -------------------------
# Run
# -------------------------
def main():
    app = PWAnalyzerGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
