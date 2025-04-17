import os
import re
import joblib
import numpy as np
from collections import Counter
from scipy import sparse

# Chargement du modèle et des outils
model = joblib.load("crypto_rf_model.pkl")
tfidf_vectorizer = joblib.load("tfidf_vectorizer.pkl")
scaler = joblib.load("scaler.pkl")
onehot = joblib.load("onehot_encoder.pkl")

VULNERABLE_ALGORITHMS = ["DES", "3DES", "RC4", "Blowfish", "SHA-1", "MD5"]

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((count/length) * np.log2(count/length) for count in counts.values())

def analyze_ciphertext(ciphertext: str, key: str, algorithm: str) -> str:
    if algorithm.upper() in [a.upper() for a in VULNERABLE_ALGORITHMS]:
        return f"{algorithm} est connu comme vulnérable - Non sécurisé !"

    cipher_clean = re.sub(r'[^a-z0-9]', '', ciphertext.lower())
    key_clean = re.sub(r'[^a-z0-9]', '', key.lower() if key else "missingkey")
    combined_text = cipher_clean + ' ' + key_clean
    entropy = shannon_entropy(cipher_clean)
    digit_ratio = sum(ch.isdigit() for ch in cipher_clean) / len(cipher_clean) if len(cipher_clean) > 0 else 0.0

    X_text = tfidf_vectorizer.transform([combined_text])
    X_num = scaler.transform([[len(cipher_clean), len(key_clean), entropy, digit_ratio]])
    X_alg = onehot.transform([[algorithm.upper()]])
    X_input = sparse.hstack([X_text, sparse.csr_matrix(X_num), X_alg])

    y_score = model.predict_proba(X_input.toarray())[0][1]
    y_pred = 1 if y_score >= 0.4 else 0

    return (
        f" Chiffrement potentiellement vulnérable ({algorithm}) - Non sécurisé !"
        if y_pred else
        f" Chiffrement sécurisé ({algorithm}) - Sécurisé."
    )

# 🔎 Test
test_cases = [
    ("3AB45CF912DEFA56C7890B12E345F678", "WeakRC4Key123", "RC4"),
    ("A1B2C3D4E5F67890", "SecureAESKey", "AES"),
    ("9fdf2bc8990abde", "", "RSA"),
]

for ciphertext, key, algo in test_cases:
    print(analyze_ciphertext(ciphertext, key, algo))
