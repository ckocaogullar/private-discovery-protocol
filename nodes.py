# Ceren Kocaoğullar, ck596
# University of Cambridge
# MPhil in Advanced Computer Science Project 2020-2021
# Simulation for A Private Node Discovery Protocol for Anonymous Networks

import rsa
import shamir_mnemonic as shamir
import uuid
import random
from SSSA import sssa
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

discovery_nodes = list()
threshold = 3
sss = sssa()


class Node:
    def __init__(self):
        (pubkey, privkey) = rsa.newkeys(256)
        key = RSA.generate(2048)
        self.pubkey = key.publickey().export_key()
        self.privkey = key.export_key()
        self.id = str(uuid.uuid4())
        self.loc = str(uuid.uuid4())

    def encrypt(self, data, recipient_key):
        # Since we want to be able to encrypt an arbitrary amount of data,
        # we use a hybrid encryption scheme. We use RSA with PKCS#1 OAEP for asymmetric encryption
        # of an AES session key. The session key can then be used to encrypt all the actual data.

        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(recipient_key))
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(
            bytes(data, encoding='utf-8'))

        return (enc_session_key, cipher_aes.nonce, tag, ciphertext)

    def decrypt(self, data_tuple):
        enc_session_key, nonce, tag, ciphertext = [x for x in data_tuple]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.privkey))
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode("utf-8")


class User(Node):
    #print(sss.combine([secrets[0], secrets[1], secrets[3]]))
    global sss
    global discovery_nodes

    def __init__(self, *args):
        super().__init__()
        secret = self.pubkey + b' ' + bytes(self.loc, encoding='utf-8')
        self.secret = secret if (len(secret) % 2 == 0) else secret + b' '
        if len(args) == 1:
            if isinstance(args[0], str):
                self.id = args[0]
            else:
                raise TypeError("Only strings are allowed as user IDs.")
        elif len(args) > 1:
            raise Exception(
                "User constructor can only be called with one parameter (user ID) or none.")

    def join_network(self):
        pass

    def request_registration(self):
        # Send registration request to a randomly selected discovery server
        selected_discovery_server = random.choice(discovery_nodes)
        return selected_discovery_server.initiate_registration(self)

    def register(self):
        # Split the secret (user ID and network location) into n pieces
        n = len(discovery_nodes)
        #secret_pieces = self._divide_secret(self.secret, threshold, n)
        #secret_pieces = shamir.generate_mnemonics(1, [(threshold, n)], self.secret)[0]
        secret_pieces = self._divide_secret(self.secret, threshold, n)
        
        print(secret_pieces)
        if self.request_registration():
            for i in range(n):
                registration_message = self.id + ', ' + secret_pieces[i]
                d_pubkey = discovery_nodes[i].pubkey
                encrypted_registration_message = self.encrypt(
                    registration_message, d_pubkey)
                discovery_nodes[i].register(encrypted_registration_message)

    def _divide_secret(self, secret, k, n):
        return sss.create(k, n, self.secret)

    def _combine_secret(self, secret_pieces):
        return sss.combine(secret_pieces)


class DiscoveryNode(Node):
    global discovery_nodes

    def __init__(self):
        super().__init__()
        self.user_registry = dict()
        discovery_nodes.append(self)

    def initiate_registration(self, user):
        # TODO: Registration initiation according to the discussions we had in our meeting
        return True

    def register(self, encrypted_message):
        message = self.decrypt(encrypted_message)
        print(message)
        user_id = str(message).split(',')[0].strip()
        secret_piece = str(message).split(',')[1].strip()
        self.user_registry[user_id] = secret_piece


def get_discovery_nodes():
    global discovery_nodes
    return discovery_nodes
