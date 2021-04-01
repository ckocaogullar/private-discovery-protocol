from SSSA import sssa
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

sss = sssa()

# RSA + AES Hybrid Encryption


def encrypt(data, recipient_key):
    session_key = get_random_bytes(16)
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(recipient_key))
    enc_session_key = cipher_rsa.encrypt(session_key)
    # Encrypt the data with the AES session key
    (ciphertext, tag), nonce = aes_encrypt(data, session_key)
    return (enc_session_key, nonce, tag, ciphertext), session_key


def decrypt(data_tuple, privkey):
    enc_session_key, nonce, tag, ciphertext = [x for x in data_tuple]
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(privkey))
    session_key = cipher_rsa.decrypt(enc_session_key)
    # Decrypt the data with the AES session key
    data = aes_decrypt(session_key, ciphertext, nonce)
    return data, session_key


def aes_encrypt(data, session_key):
    cipher = AES.new(session_key, AES.MODE_EAX)
    return cipher.encrypt_and_digest(bytes(data, encoding='utf-8')), cipher.nonce


def aes_decrypt(key, ciphertext, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt(ciphertext)
    return data.decode("utf-8")


def generate_key_pair():
    return RSA.generate(2048)


# Shamir's Secret Sharing

def divide_secret(secret, k, n):
    return sss.create(k, n, secret)


def combine_secret(secret_pieces):
    return sss.combine(secret_pieces)
