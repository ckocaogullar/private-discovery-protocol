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

threshold = 3
path_length = 3

sss = sssa()
discovery_nodes = list()
relay_nodes = list()
public_address_book = dict()


class Node:
    global threshold
    global path_length
    global public_address_book

    def __init__(self):
        (pubkey, privkey) = rsa.newkeys(256)
        key = RSA.generate(2048)
        self.pubkey = key.publickey().export_key()
        self.privkey = key.export_key()
        self.id = str(uuid.uuid4())
        self.loc = str(uuid.uuid4())
        self.address_book = public_address_book.copy()

    def encrypt(self, data, recipient_key):
        # We use a hybrid encryption scheme to be able to encrypt an arbitrary amount of data (RSA + AES)
        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(recipient_key))
        enc_session_key = cipher_rsa.encrypt(session_key)
        # Encrypt the data with the AES session key
        (ciphertext, tag), nonce = self.aes_encrypt(data, session_key)
        return (enc_session_key, nonce, tag, ciphertext), session_key

    def decrypt(self, data_tuple):
        enc_session_key, nonce, tag, ciphertext = [x for x in data_tuple]
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.privkey))
        session_key = cipher_rsa.decrypt(enc_session_key)
        # Decrypt the data with the AES session key
        data = self.aes_decrypt(session_key, ciphertext, nonce)
        return data, session_key

    def aes_encrypt(self, data, session_key):
        cipher = AES.new(session_key, AES.MODE_EAX)
        return cipher.encrypt_and_digest(bytes(data, encoding='utf-8')), cipher.nonce

    def aes_decrypt(self, key, ciphertext, nonce):
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt(ciphertext)
        return data.decode("utf-8")

    def pass_message(self, message):
        if len(message.header) != 0:
            next_hop = message.header.pop()
            if next_hop in self.address_book.keys():
                print(
                    f'Message is in {self.id}, next stop is {self.address_book[next_hop].id}.')
                self.address_book[next_hop].process_message(message)
                self.address_book[next_hop].pass_message(message)
            else:
                print(
                    f'{self.id} does not know node {next_hop}, dropping the message.')

    def process_message(self, message):
        # Need this empty declaration for overloading
        pass

    def prepare_message(self, targets, payload, anonymous=False):
        selected_relay_nodes = random.sample(relay_nodes, k=path_length * 2)
        path = targets + selected_relay_nodes[path_length:]
        if anonymous:
            path = [self.id] + selected_relay_nodes[:path_length] + path
        header = [x.id if isinstance(x, Node) else x for x in path]
        return Message(header, payload)

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

    def _divide_secret(self, secret, k, n):
        return sss.create(k, n, secret)

    def _combine_secret(self, secret_pieces):
        return sss.combine(secret_pieces)


class User(Node):
    global sss
    global discovery_nodes

    def __init__(self, *args):
        super().__init__()
        secret = self.pubkey + b' --USER_LOC-- ' + \
            bytes(self.loc, encoding='utf-8')
        self.secret = secret if (len(secret) % 2 == 0) else secret + b' '
        if len(args) == 1:
            if isinstance(args[0], str):
                self.id = args[0]
            else:
                raise TypeError("Only strings are allowed as user IDs.")
        elif len(args) > 1:
            raise Exception(
                "User constructor can only be called with one parameter (User ID) or none.")
        print(f'User created with ID {self.id} and location {self.loc}')

    def request_registration(self):
        # Send registration request to a randomly selected discovery server
        selected_discovery_server = random.choice(discovery_nodes)
        return selected_discovery_server.initiate_registration(self)

    def register(self, fake_id='', fake_secret=''):
        # Split the secret (user ID and network location) into n pieces
        n = len(discovery_nodes)
        secret = self.secret if not fake_secret else fake_secret
        u_id = self.id if not fake_id else fake_id
        secret_pieces = self._divide_secret(secret, threshold, n)
        if fake_id or self.request_registration():
            for i in range(n):
                registration_message = u_id + ', ' + secret_pieces[i]
                d_pubkey = discovery_nodes[i].pubkey
                encrypted_registration_message, session_key = self.encrypt(
                    registration_message, d_pubkey)
                discovery_nodes[i].register(encrypted_registration_message)
            if not fake_secret:
                for n in relay_nodes:
                    n.address_book[self.id] = self

    def lookup_user(self, user_id):
        print(
            f'Searcher with ID {self.id} is looking up searchee with ID {user_id}')
        selected_discovery_nodes = random.sample(discovery_nodes, k=threshold)
        payload = list()
        self.sym_keys = list()
        for node in selected_discovery_nodes:
            tup, session_key = self.encrypt(user_id, node.pubkey)
            enc_session_key, nonce, tag, ciphertext = [x for x in tup]
            self.sym_keys.append((session_key, nonce))
            payload.append(tup)
        message = self.prepare_message(
            selected_discovery_nodes, payload, anonymous=True)
        self.pass_message(message)

    def process_message(self, message):
        message_type = self._detect_message_type(message)
        if message_type == 'DISCOVERY':
            self._complete_lookup(message)
        elif message_type == 'PING':
            sender, sender_pubkey, sender_loc = [
                x.strip() for x in self.decrypt(message.payload)[0].split('separator')[1:]]
            if self._authenticate_user(sender):
                print(
                    f'Searcher with ID {sender} and location {sender_loc} authenticated by searchee {self.id}')
                self.address_book[sender] = (sender_pubkey, sender_loc)
        else:
            print(
                f'Received a regular message with payload {self.decrypt(message.payload)[0]}')

    def ping_user(self, user_id):
        payload, session_key = self.encrypt(
            'ping' + 'separator' + self.id + 'separator' + str(self.pubkey) + 'separator' + self.loc, self.address_book[user_id][0])
        message = self.prepare_message([user_id], payload)
        self.pass_message(message)

    def _authenticate_user(self, user_id):
        # Return True for now. Normally it will send a message encrypted with searcher’s pubkey.
        return True

    def _complete_lookup(self, message):
        secrets = []
        for i in range(len(message.payload)):
            decrypted_message = self.aes_decrypt(
                self.sym_keys[i][0], message.payload[i][0], message.payload[i][1]).split()
            secrets.append(decrypted_message[1])
        searchee_id = decrypted_message[0]
        combined_secret = self._combine_secret(
            secrets).split(' --USER_LOC-- ')
        searchee_pubkey = combined_secret[0].strip()
        searchee_loc = combined_secret[1].strip()
        print(f'{self.id} completed their lookup for {searchee_id}. Adding to the address book as public key: {searchee_pubkey} and location {searchee_loc}')
        self.address_book[searchee_id] = (searchee_pubkey, searchee_loc)
        print(f'{self.id} pinging {searchee_id}')
        self.ping_user(searchee_id)

    def _detect_message_type(self, message):
        if isinstance(message.payload, list):
            return 'DISCOVERY'
        elif 'ping' in self.decrypt(message.payload)[0]:
            return 'PING'
        else:
            return 'DEFAULT'


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
        message, session_key = self.decrypt(encrypted_message)
        user_id = str(message).split(',')[0].strip()
        secret_piece = str(message).split(',')[1].strip()
        print(
            f'Discovery node {self.id} registering user {user_id}')
        self.user_registry[user_id] = secret_piece

    def process_message(self, message):
        # Process discovery message. Payload consists of a list of data tuples.
        # Each of the data tuples is encrypted with one discovery server's pubkey.
        user_id, session_key = self.decrypt(message.payload.pop())
        if user_id not in self.user_registry.keys():
            # Create a fake user entry
            fake_pubkey = RSA.generate(2048).publickey().export_key()
            fake_loc = str(uuid.uuid4())
            secret = fake_pubkey + b' --USER_LOC-- ' + \
                bytes(fake_loc, encoding='utf-8')
            fake_secret = secret if (len(secret) % 2 == 0) else secret + b' '
            print(
                f'Discovery node {self.id} created a fake user record with ID {user_id} and secret {secret}')
            User.register(self, fake_id=user_id, fake_secret=fake_secret)
        ciphertext, nonce = self.aes_encrypt(
            user_id + ' ' + self.user_registry[user_id], session_key)
        message.payload.insert(0, [ciphertext[0], nonce])
        self.pass_message(message)


class Message:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload


def initiate_network(num_discovery_nodes, num_relay_nodes, num_users):
    global discovery_nodes
    global relay_nodes
    global public_address_book

    for i in range(num_discovery_nodes):
        node = DiscoveryNode()
        print(f'Discovery node created with ID {node.id}')
        public_address_book[node.id] = node

    for i in range(num_relay_nodes):
        node = Node()
        relay_nodes.append(node)
        print(f'Relay node created with ID {node.id}')
        public_address_book[node.id] = node

    for i in range(num_users):
        node = User()
        print(f'User created with ID {node.id}')

    for node in discovery_nodes:
        node.address_book = public_address_book.copy()

    for node in relay_nodes:
        node.address_book = public_address_book.copy()
