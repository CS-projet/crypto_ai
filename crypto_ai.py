import os
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
from cipher_utils import encrypt_text, decrypt_text

# Charger le modèle IA entraîné pour l'analyse des vulnérabilités
MODEL_PATH = "crypto_analyzer.h5"
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"❌ Le fichier {MODEL_PATH} est introuvable. Assurez-vous qu'il est généré par model_training.py.")

model = load_model(MODEL_PATH)

# Liste des algorithmes vulnérables connus
VULNERABLE_ALGORITHMS = ["DES", "3DES", "RC4", "Blowfish", "SHA-1", "MD5"]

def analyze_ciphertext(ciphertext: str, key: str, algorithm: str) -> str:
    """
    Analyse un texte chiffré et prédit s'il est vulnérable ou non.
    """
    # Vérifier si l'algorithme est déjà connu comme vulnérable
    if algorithm in VULNERABLE_ALGORITHMS:
        return f"⚠️ {algorithm} est connu comme vulnérable - ❌ Non sécurisé !"
    
    # Préparer les données pour le modèle IA
    input_data = np.array([[ciphertext, key, algorithm]])
    prediction = model.predict(input_data)
    
    # Vérifier si le modèle détecte une vulnérabilité
    is_vulnerable = prediction[0][0] > 0.5
    
    return (
        f"⚠️ Chiffrement potentiellement vulnérable ({algorithm}) - ❌ Non sécurisé !"
        if is_vulnerable else 
        f"✅ Chiffrement sécurisé ({algorithm}) - 🔒 Sécurisé."
    )

# Exemple d'utilisation
test_cases = [
    ("3AB45CF912DEFA56C7890B12E345F678", "WeakRC4Key123", "RC4"),  # Vulnérable
    ("A1B2C3D4E5F67890", "SecureAESKey", "AES"),  # Sécurisé
]

for ciphertext, key, algo in test_cases:
    print(analyze_ciphertext(ciphertext, key, algo))
