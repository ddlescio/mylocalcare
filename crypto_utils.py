# utils/crypto_utils.py
import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Parametri Scrypt: sicuri ma ancora rapidi su server standard.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEK_LEN = 32          # 256 bit per AES-256-GCM
DEK_LEN = 32          # 256 bit per cifrare i contenuti
NONCE_LEN = 12        # 96 bit, raccomandato per AES-GCM
SALT_LEN = 16         # per Scrypt

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def derive_kek(password: str, salt_b64: str) -> bytes:
    """
    Deriva una KEK (key-encryption key) dalla password utente usando Scrypt+salt (base64).
    """
    salt = _b64d(salt_b64)
    kdf = Scrypt(salt=salt, length=KEK_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))

def new_salt() -> str:
    return _b64e(os.urandom(SALT_LEN))

def new_dek() -> str:
    """Genera una DEK random (base64) che useremo per cifrare i messaggi dell'utente."""
    return _b64e(os.urandom(DEK_LEN))

def encrypt_with_key(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[str, str]:
    """
    Cifra (AES-256-GCM) e restituisce (ciphertext_b64, nonce_b64).
    AESGCM in Python include già il tag nel ciphertext.
    """
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aes.encrypt(nonce, plaintext, aad or None)
    return _b64e(ct), _b64e(nonce)

def decrypt_with_key(key: bytes, ciphertext_b64: str, nonce_b64: str, aad: bytes = b"") -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(_b64d(nonce_b64), _b64d(ciphertext_b64), aad or None)

# --- Operazioni "wrap/unwrap" della DEK con KEK (password-derivata) ---

def wrap_dek_with_password(password: str, dek_b64: str, salt_b64: str = None) -> dict:
    """
    Genera (se mancante) un salt per Scrypt, deriva la KEK dalla password e cifra la DEK.
    Ritorna dict con: dek_enc, dek_nonce, key_salt.
    """
    key_salt = salt_b64 or new_salt()
    kek = derive_kek(password, key_salt)
    dek_ct, dek_nonce = encrypt_with_key(kek, _b64d(dek_b64))
    return {
        "dek_enc": dek_ct,
        "dek_nonce": dek_nonce,
        "key_salt": key_salt
    }

def unwrap_dek_with_password(password: str, dek_enc_b64: str, dek_nonce_b64: str, key_salt_b64: str) -> str:
    """
    Decifra la DEK cifrata usando la password (derivando la KEK).
    Ritorna la DEK in base64 (stringa).
    """
    kek = derive_kek(password, key_salt_b64)
    dek = decrypt_with_key(kek, dek_enc_b64, dek_nonce_b64)
    return _b64e(dek)

# --- Cifratura/decifratura dei messaggi utente con la DEK ---

def encrypt_message(dek_b64: str, message_text: str) -> Tuple[str, str]:
    key = _b64d(dek_b64)
    ct_b64, nonce_b64 = encrypt_with_key(key, message_text.encode("utf-8"))
    return ct_b64, nonce_b64

def decrypt_message(dek_b64: str, ciphertext_b64: str, nonce_b64: str) -> str:
    key = _b64d(dek_b64)
    pt = decrypt_with_key(key, ciphertext_b64, nonce_b64)
    return pt.decode("utf-8")
