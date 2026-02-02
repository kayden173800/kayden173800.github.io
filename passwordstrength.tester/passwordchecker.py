#!/usr/bin/env python3
import math
import re

COMMON_WORDS = {"password","123456","qwerty","letmein","admin"}  # extend from file

SYMBOLS = r"""!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

def char_space_size(pw: str) -> int:
    s = 0
    if re.search(r'[a-z]', pw): s += 26
    if re.search(r'[A-Z]', pw): s += 26
    if re.search(r'[0-9]', pw): s += 10
    if re.search(r'[' + re.escape(SYMBOLS) + r']', pw): s += 33  # approximate
    return s if s > 0 else 1

def entropy_bits(pw: str) -> float:
    space = char_space_size(pw)
    return len(pw) * math.log2(space)

def classify_entropy(bits: float) -> str:
    # conservative thresholds you can tune
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
    # simplistic repeated char check
    if re.search(r'(.)\1\1', pw):
        issues.append("Has repeated characters")
    # dictionary / common-password check (simple)
    if pw.lower() in COMMON_WORDS:
        issues.append("Common password or in blacklist")
    return issues

def analyze(pw: str):
    bits = entropy_bits(pw)
    label = classify_entropy(bits)
    issues = policy_checks(pw)
    recommendations = []
    if bits < 36 or issues:
        recommendations.append("Use a longer passphrase (4+ random words)")
        recommendations.append("Avoid common words; add uncommon separators or punctuation")
    return {
        "password": pw,
        "length": len(pw),
        "entropy_bits": round(bits, 2),
        "strength": label,
        "issues": issues,
        "recommendations": recommendations
    }

if __name__ == "__main__":
    import json, sys
    pw = sys.argv[1] if len(sys.argv) > 1 else input("Password to analyze: ")
    print(json.dumps(analyze(pw), indent=2))
