# Ceren Kocaoğullar, ck596
# University of Cambridge
# MPhil in Advanced Computer Science Project 2020-2021
# Simulation for A Private Node Discovery Protocol for Anonymous Networks


import uuid
import random
import crypto
from network import Network

THRESHOLD = 3
PATH_LENGTH = 3


class Node:
    def __init__(self, network):
        key = crypto.generate_key_pair()
        self.pubkey = key.publickey().export_key()
        self.privkey = key.export_key()
        self.id = str(uuid.uuid4())
        self.loc = str(uuid.uuid4())
        self.network = network
        self.address_book = self.network.public_address_book.copy()

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
        # Need this declaration for overloading
        pass

    def prepare_message(self, targets, payload, anonymous=False):
        selected_relay_nodes = random.sample(
            self.network.relay_nodes, k=PATH_LENGTH * 2)
        path = targets + selected_relay_nodes[PATH_LENGTH:]
        if anonymous:
            path = [self.id] + selected_relay_nodes[:PATH_LENGTH] + path
        header = [x.id if isinstance(x, Node) else x for x in path]
        return Message(header, payload)


class User(Node):
    def __init__(self, *args):
        assert 0 < len(
            args) <= 2, "User constructor can only be called with one or two parameters: Network and [(User ID) or none]."
        assert isinstance(
            args[0], Network), "The user must take network as the first parameter."
        super().__init__(args[0])
        if len(args) == 2:
            assert isinstance(
                args[1], str), "Only strings are allowed as user IDs."
            self.id = args[1]
        secret = self.pubkey + b' --USER_LOC-- ' + \
            bytes(self.loc, encoding='utf-8')
        self.secret = secret if (len(secret) % 2 == 0) else secret + b' '

        print(f'User created with ID {self.id} and location {self.loc}')

    def request_registration(self):
        # Send registration request to a randomly selected discovery server
        selected_discovery_server = random.choice(self.network.discovery_nodes)
        selected_discovery_servers = random.sample(
            self.network.discovery_nodes, THRESHOLD)
        return selected_discovery_server.initiate_registration(self, selected_discovery_servers)

    def register(self, fake_id='', fake_secret=''):
        # Split the secret (user ID and network location) into n pieces
        n = len(self.network.discovery_nodes)
        secret = self.secret if not fake_secret else fake_secret
        u_id = self.id if not fake_id else fake_id
        secret_pieces = crypto.divide_secret(secret, THRESHOLD, n)
        targets = self.network.discovery_nodes.copy()
        payload = list()
        if fake_id or self.request_registration():
            for i in range(n):
                registration_message = 'registration_flag' + \
                    u_id + ', ' + secret_pieces[i]
                d_pubkey = self.network.discovery_nodes[i].pubkey
                encrypted_registration_msg = crypto.encrypt(
                    registration_message, d_pubkey)[0]
                payload.append(encrypted_registration_msg)
                payload.insert(0, 'REGISTRATION')
            message = self.prepare_message(targets, payload)
            self.pass_message(message)
            if not fake_secret:
                for n in self.network.relay_nodes:
                    n.address_book[self.id] = self
        return secret

    def lookup_user(self, user_id):
        print('\n---------------------------------------------')
        print('--------------STARTING LOOKUP----------------')
        print('---------------------------------------------\n')
        print(
            f'Searcher with ID {self.id} is looking up searchee with ID {user_id}')
        selected_discovery_nodes = random.sample(
            self.network.discovery_nodes, k=THRESHOLD)
        payload = list()
        self.sym_keys = list()
        for node in selected_discovery_nodes:
            encrypted_discovery_msg, session_key = crypto.encrypt(
                'discovery_flag' + user_id, node.pubkey)
            nonce = encrypted_discovery_msg[1]
            self.sym_keys.append((session_key, nonce))
            payload.append(encrypted_discovery_msg)
        message = self.prepare_message(
            selected_discovery_nodes, payload, anonymous=True)
        self.pass_message(message)

    def process_message(self, message):
        message_type = message.detect_type()
        if message_type == 'DISCOVERY':
            self._complete_lookup(message)
        elif message_type == 'PING':
            sender, sender_pubkey, sender_loc = [
                x.strip() for x in crypto.decrypt(message.payload, self.privkey)[0].split('separator')[1:]]
            if self._authenticate_searcher(sender):
                print(
                    f'Searcher with ID {sender} and location {sender_loc} authenticated by searchee {self.id}')
                self.address_book[sender] = (sender_pubkey, sender_loc)
        else:
            print(
                f'Received a regular message with payload {crypto.decrypt(message.payload, self.privkey)[0]}')

    def ping_user(self, user_id):
        payload, session_key = crypto.encrypt(
            'ping_flag' + 'separator' + self.id + 'separator' + str(self.pubkey) + 'separator' + self.loc, self.address_book[user_id][0])
        message = self.prepare_message([user_id], payload)
        self.pass_message(message)

    def _authenticate_searcher(self, user_id):
        # Return True for now. Normally it will send a message encrypted with searcher’s pubkey.
        return True

    def _complete_lookup(self, message):
        secrets = []
        for i in range(len(message.payload)):
            decrypted_message = crypto.aes_decrypt(
                self.sym_keys[i][0], message.payload[i][0], message.payload[i][1]).split()
            secrets.append(decrypted_message[1])
        searchee_id = decrypted_message[0]
        combined_secret = crypto.combine_secret(
            secrets).split(' --USER_LOC-- ')
        searchee_pubkey = combined_secret[0].strip()
        searchee_loc = combined_secret[1].strip()
        print(f'\n{self.id} completed their lookup for {searchee_id}. Adding to the address book as public key: {searchee_pubkey} and location {searchee_loc}')
        self.address_book[searchee_id] = (searchee_pubkey, searchee_loc)
        print('\n---------------------------------------------')
        print('--------------LOOKUP COMPLETED----------------')
        print('---------------------------------------------\n')
        print(f'{self.id} pinging {searchee_id}')
        self.ping_user(searchee_id)


class DiscoveryNode(Node):
    def __init__(self, network):
        super().__init__(network)
        self.user_registry = dict()
        self.network.discovery_nodes.append(self)

    def initiate_registration(self, user, selected_discovery_nodes):
        """
        Dummy function for now. This function will initiate registration by authenticating the user through two-factor authentication
        using DKIM signatures to check the integrity of the authentication email. 

        Verifying DKIM signatures involves checking DNS records for the server.
        To fit this into my threat model, k (THRESHOLD) number of discovery nodes should perform this verification
        and if all of them verify that the response email from the sender is unaltered and genuine, this function should
        return True. Otherwise, it should return False.
        """
        return True

    def process_message(self, message):
        """
        Process discovery message. Payload consists of a list of data tuples.
        Each of the data tuples is encrypted with one discovery server's pubkey.
        """
        encrypted_payload = message.payload.pop()
        decrypted_payload, session_key = crypto.decrypt(
            encrypted_payload, self.privkey)
        if message.detect_type() == 'REGISTRATION':
            user_id, secret_piece = [x.strip() for x in decrypted_payload.replace(
                'registration_flag', '').split(',')]
            print(f'\nDiscovery node {self.id} registering user {user_id}')
            self.user_registry[user_id] = secret_piece
            message.payload.insert(1, encrypted_payload)
        elif message.detect_type() == 'DISCOVERY':
            user_id = decrypted_payload.replace('discovery_flag', '').strip()
            if user_id not in self.user_registry.keys():
                print(
                    f'\nUser with ID {user_id} does not exist. Creating a fake user record.\n')
                secret = self.create_fake_user(user_id)
                print(
                    f'\nDiscovery node {self.id} created a fake user record with ID {user_id} and secret {secret}\n')
            ciphertext, nonce = crypto.aes_encrypt(
                user_id + ' ' + self.user_registry[user_id], session_key)
            message.payload.insert(0, [ciphertext[0], nonce])
        self.pass_message(message)

    def create_fake_user(self, user_id):
        fake_pubkey = crypto.generate_key_pair().publickey().export_key()
        fake_loc = str(uuid.uuid4())
        secret = fake_pubkey + b' --USER_LOC-- ' + \
            bytes(fake_loc, encoding='utf-8')
        fake_secret = secret if (len(secret) % 2 == 0) else secret + b' '
        return User.register(self, fake_id=user_id, fake_secret=fake_secret)


class Message:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

    def detect_type(self):
        if isinstance(self.payload, list):
            if self.payload[0] == 'REGISTRATION':
                return 'REGISTRATION'
            return 'DISCOVERY'
        else:
            return 'PING'
