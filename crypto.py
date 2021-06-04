# Python modules
import random
import math
import hashlib

# External libraries / modules
from SSSA import sssa
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


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
    assert 4 == len(
        data_tuple), "Data tuple has too many or too few elements"
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
    key = RSA.generate(2048)
    pubkey = key.publickey().export_key()
    privkey = key.export_key()
    return pubkey, privkey


# Shamir's Secret Sharing
sss = sssa()


def divide_secret(secret, k, n):
    return sss.create(k, n, secret)


def combine_secret(secret_pieces):
    return sss.combine(secret_pieces)


# Digital Signature

def sign(key, msg):
    signer = pkcs1_15.new(RSA.import_key(key))
    msg = bytes(msg, encoding='utf-8')
    hash = SHA256.new(msg)
    return signer.sign(hash)


def verify(key, signature, msg):
    try:
        verifier = pkcs1_15.new(RSA.import_key(key))
        msg = bytes(msg, encoding='utf-8')
        hash = SHA256.new(msg)
        verifier.verify(hash, signature)
        print('Signature is valid')
        return True
    except (ValueError, TypeError):
        print('Signature is not valid')
        return False

# OPRF-related


def hash_with_salts(salts, string):
    string = bytes(string, encoding='utf-8')
    for salt in salts:
        hashed_str = hashlib.new('sha256', string)
        string += bytes(salt, encoding='utf-8')
    return hashed_str.hexdigest()


def oprf(key_holder, input):
    """
    Dummy function for now, does not really run an OPRF protocol or have any cryptographic base.
    Seeds the python random function with the searchee (searched user) ID and a secret value of the discovery server
    This allows users to get the same pseudorandom salt value for the same user ID from the same discovery server 
    without learning the discovery server's secret salt. However, in this dummy implementation, the discovery server
    learns the searchee ID. 

    OPRF will be used to allow the searchers to obtain fixed pseudorandom salt values for each searchee, without revealing
    the searchee ID or learning the server's secret salt.
    """
    random.seed(input + key_holder.oprf_key)
    return str(random.randint(math.pow(2, 8), math.pow(2, 16)))
