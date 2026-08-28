import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
import jwt


def account_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def signing_key():
    return ec.generate_private_key(ec.SECP256R1())


def session_key():
    return x25519.X25519PrivateKey.generate()


def legacy_hash(data):
    return hashlib.md5(data).hexdigest()


def digest(data):
    return hashes.SHA256()


def encrypt(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher.encryptor().update(data)


def pycryptodome_encrypt(key, data):
    return AES.new(key, AES.MODE_GCM).encrypt(data)


def stretch(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw, salt, 600000)


def issue(payload, key):
    return jwt.encode(payload, key, algorithm='ES256')
