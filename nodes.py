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
relay_nodes = list()
threshold = 3
path_length = 3
sss = sssa()
public_address_book = dict()


class Node:
    def __init__(self):
        (pubkey, privkey) = rsa.newkeys(256)
        key = RSA.generate(2048)
        self.pubkey = key.publickey().export_key()
        self.privkey = key.export_key()
        self.id = str(uuid.uuid4())
        self.loc = str(uuid.uuid4())
        self.address_book = public_address_book

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

    def pass_message(self, message):
        if message.header[0] == '':
            print(f"I have received the message. My id is {self.id}")
            self.process_message(message)
        else:
            if isinstance(message.header, tuple):
                peeled_header = self.decrypt(message.header)
                print(f'peeled header is')
            next_hop = peeled_header.split('+')[0]
            next_header = self._str_to_tuple(peeled_header.split('+')[1])
            message.header = next_header
            return self.address_book[next_hop].process_message(message)

    def process_message(self, message):
        self.decrypt(message.payload)

    def build_header(self, path):
        header = ""
        for i in range(len(path)):
            header = self.encrypt(
                self._tuple_to_str(header) + '+' + path[len(path)-2-i].id, path[len(path)-1-i].pubkey)
        return header

    def _tuple_to_str(self, tup):
        string = ''
        for i in range(len(tup)):
            string += str(tup[i])
            if i != 0 and i != len(tup) - 1:
                string += ''
        return string

    def _str_to_tuple(self, string):
        lst = string.split(',')
        return tuple(lst)


class User(Node):
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

        secret_pieces = self._divide_secret(self.secret, threshold, n)

        # print(secret_pieces)
        if self.request_registration():
            for i in range(n):
                registration_message = self.id + ', ' + secret_pieces[i]
                d_pubkey = discovery_nodes[i].pubkey
                encrypted_registration_message = self.encrypt(
                    registration_message, d_pubkey)
                discovery_nodes[i].register(encrypted_registration_message)

    def lookup_user(self, user_id):
        selected_discovery_nodes = random.sample(discovery_nodes, k=threshold)

        # Picking path_length * 2 relay nodes for the way to and from discovery nodes.
        selected_relay_nodes = random.sample(relay_nodes, k=path_length * 2)
        header = self.build_header(
            [self] + selected_relay_nodes[:path_length] + selected_discovery_nodes + selected_relay_nodes[path_length:] + [self])
        payload = list()
        for node in selected_discovery_nodes:
            payload.append(self.encrypt(self.id, node.pubkey))

        self.pass_message(Message(header, payload))

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
        # print(message)
        user_id = str(message).split(',')[0].strip()
        secret_piece = str(message).split(',')[1].strip()
        self.user_registry[user_id] = secret_piece

    def process_message(self, message):
        # Process discovery message. Payload consists of a list of data tuples.
        # Each of the data tuples is encrypted with one discovery server's pubkey.
        for payload in message.payload:
            print(
                f'I am discovery node {self.id}, decrypting {self.decrypt(payload)}')
            print(self.decrypt(payload))
        self.pass_message(message)


class Message:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload


def get_discovery_nodes():
    global discovery_nodes
    return discovery_nodes


def initiate_network(num_discovery_nodes, num_relay_nodes, num_users):
    global discovery_nodes
    global relay_nodes
    global public_address_book

    for i in range(num_discovery_nodes):
        discovery_nodes.append(DiscoveryNode())

    for i in range(num_relay_nodes):
        relay_nodes.append(Node())

    for i in range(num_users):
        User()

    for node in discovery_nodes:
        public_address_book[node.id] = node

    for node in relay_nodes:
        public_address_book[node.id] = node
