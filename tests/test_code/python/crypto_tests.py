import hashlib
from Crypto.Cipher import AES

def insecure_hash(data):
    # VULNERABLE: WEAK_CRYPTO (MD5 via Regex & AST)
    h = hashlib.md5(data.encode())
    return h.hexdigest()

def insecure_cipher(key, data):
    # VULNERABLE: WEAK_CRYPTO (AES-ECB)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def safe_hash(data):
    # SAFE: SHA256
    return hashlib.sha256(data.encode()).hexdigest()
