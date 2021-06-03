"""
Ceren Kocaoğullar, ck596
University of Cambridge
MPhil in Advanced Computer Science Project 2020-2021
Simulation Tool for Privacy-Preserving User Discovery in Anonymous Communication Networks
"""

# Python modules
import random
import string

# Inter-project modules
from network import Network
from const import PATH_LENGTH, THRESHOLD, UserEntry, ErrorCodes, MessageType, PuddingType
import crypto
import math


class Node:
    def __init__(self, network):
        # Public - private key pair for encrypting all communications
        self.pubkey, self.privkey = crypto.generate_key_pair()

        # Pseudorandom strings as Node ID and location
        self.id = ''.join(random.SystemRandom().choice(
            string.ascii_uppercase + string.digits) for _ in range(3))
        self.loc = ''.join(random.SystemRandom().choice(
            string.ascii_uppercase + string.digits) for _ in range(3))
        
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
                self.address_book.keys()
                print(
                    f'{self.id} does not know node {next_hop}, dropping the message.')

    def process_message(self, message):
        # Need this declaration for overloading
        pass

    def prepare_message(self, target, payload, type, anonymous=False):
        selected_relay_nodes = random.sample(
            self.network.relay_nodes, k=PATH_LENGTH * 2)
        path = [target] + selected_relay_nodes[PATH_LENGTH:]
        if anonymous:
            path = [self.id] + selected_relay_nodes[:PATH_LENGTH] + path
        header = [x.id if isinstance(x, Node) else x for x in path]
        return Message(header, payload, type)

    def update_address_book(self, key, node):
        self.address_book[key] = node


class User(Node):
    def __init__(self, *args):
        # Input checks
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

        # User's contact information is their secret. Padding the value for secret sharing.
        self.secret = secret if (len(secret) % 2 == 0) else secret + b' '
    
        # A buffer for received lookup responses. This list consists of elements that are tuples of type (discovery_node_id, response_message)
        self.lookup_response_buffer = list()

        # Digital signature public verification key (svk), private signing key pair (ssk)
        self.svk, self.ssk = crypto.generate_key_pair()

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
        if self.network.pudding_type == PuddingType.ID_VERIFIED:
            if self.request_registration():
                # Make yourself known to discovery nodes
                for relay_node in self.network.relay_nodes:
                    relay_node.update_address_book(self.id, self)
                # Register to discovery nodes
                for target in self.network.discovery_nodes.copy():
                    registration_message = u_id + ', ' + \
                        secret_pieces.pop() + ', ' + str(self.svk)
                    d_pubkey = target.pubkey
                    encrypted_registration_msg = crypto.encrypt(
                        registration_message, d_pubkey)[0]
                    payload = encrypted_registration_msg
                    message = self.prepare_message(target, payload, 'REGISTRATION')
                    self.pass_message(message)
            elif self.network.pudding_type == PuddingType.INCOGNITO:
                # Get pseudorandom salt values using OPRF for the registering user's ID
                for discovery_node in self.network.discovery_nodes:
                    salt_dict[discovery_node] = discovery_node.oprf(self.id)
                """
                Prepare salted hashes for each discovery server.

                Each discovery server D receives (THRESHOLD-1)-combination-of-all-discovery-servers-many hash values per user.
                These hashes are used as keys to find the user's secret piece stored in that discovery server. 
                Each of these hashes use salts of one THRESHOLD-combination-of-all-discovery-servers that include D.
                """
                for discovery_node in self.network.discovery_nodes:
                    combinations_with_discovery_node = [
                        x for x in self.network.discovery_node_combinations if discovery_node in x]
                    assert len([x for x in combinations_with_discovery_node if discovery_node not in x]
                            ) == 0, "Discovery node combinations are picked wrong for the discovery servers"
                    assert int(math.factorial(len(self.network.discovery_nodes) - 1) / (math.factorial(THRESHOLD - 1) * math.factorial(
                        len(self.network.discovery_nodes) - THRESHOLD))) == len(combinations_with_discovery_node), "Number of picked combinations is off"
                    print(f'{self.id} registering to discovery node {discovery_node.id}')
                    for comb in combinations_with_discovery_node:
                        print(
                            f'Registering to node {discovery_node.id} with combination {[x.id for x in comb]} and salts {[salt_dict[d] for d in comb]}')
                        multi_salted_hash = crypto.hash_with_salts(
                            [salt_dict[d] for d in comb], self.id)
                        registration_message += ', ' + multi_salted_hash
                    print(f'registration_message {registration_message}')
                    registration_message += ', ' + secret_pieces.pop()
                    encrypted_registration_msg = crypto.encrypt(
                        registration_message, discovery_node.pubkey)[0]
                    payload.append(encrypted_registration_msg)
                    payload.insert(0, 'REGISTRATION')
                message = self.prepare_message(targets, payload)
                self.pass_message(message)

    
        def incognito_register(self):
        # Split the secret (user ID and network location) into n pieces
        n = len(self.network.discovery_nodes)
        secret_pieces = crypto.divide_secret(self.secret, THRESHOLD, n)
        targets = self.network.discovery_nodes.copy()
        payload = list()
        salt_dict = dict()
        # Get pseudorandom salt values using OPRF for the registering user's ID
        for discovery_node in self.network.discovery_nodes:
            salt_dict[discovery_node] = discovery_node.oprf(self.id)
        """
        Prepare salted hashes for each discovery server.

        Each discovery server D receives (THRESHOLD-1)-combination-of-all-discovery-servers-many hash values per user.
        These hashes are used as keys to find the user's secret piece stored in that discovery server. 
        Each of these hashes use salts of one THRESHOLD-combination-of-all-discovery-servers that include D.
        """
        for discovery_node in self.network.discovery_nodes:
            registration_message = 'registration_flag'
            combinations_with_discovery_node = [
                x for x in self.network.discovery_node_combinations if discovery_node in x]
            assert len([x for x in combinations_with_discovery_node if discovery_node not in x]
                       ) == 0, "Discovery node combinations are picked wrong for the discovery servers"
            assert int(math.factorial(len(self.network.discovery_nodes) - 1) / (math.factorial(THRESHOLD - 1) * math.factorial(
                len(self.network.discovery_nodes) - THRESHOLD))) == len(combinations_with_discovery_node), "Number of picked combinations is off"
            print(f'{self.id} registering to discovery node {discovery_node.id}')
            for comb in combinations_with_discovery_node:
                print(
                    f'Registering to node {discovery_node.id} with combination {[x.id for x in comb]} and salts {[salt_dict[d] for d in comb]}')
                multi_salted_hash = crypto.hash_with_salts(
                    [salt_dict[d] for d in comb], self.id)
                registration_message += ', ' + multi_salted_hash
            print(f'registration_message {registration_message}')
            registration_message += ', ' + secret_pieces.pop()
            encrypted_registration_msg = crypto.encrypt(
                registration_message, discovery_node.pubkey)[0]
            payload.append(encrypted_registration_msg)
            payload.insert(0, 'REGISTRATION')
        message = self.prepare_message(targets, payload)
        self.pass_message(message)

    def lookup_user(self, user_id):
        print('\n---------------------------------------------')
        print('--------------STARTING LOOKUP----------------')
        print('---------------------------------------------\n')
        print(
            f'Searcher with ID {self.id} is looking up searchee with ID {user_id}')
        selected_discovery_nodes = random.sample(
            self.network.discovery_nodes, k=THRESHOLD)
        payload = list()
        self.sym_keys = dict()
        for node in selected_discovery_nodes:
            encrypted_discovery_msg, session_key = crypto.encrypt(
                user_id, node.pubkey)
            nonce = encrypted_discovery_msg[1]
            self.sym_keys[node.id] = (session_key, nonce)
            payload = encrypted_discovery_msg
            message = self.prepare_message(
                node, payload, 'DISCOVERY', anonymous=True)
            self.pass_message(message)

    def process_message(self, message):
        message_type = message.detect_type()
        if message_type == 'DISCOVERY':
            print(
                f'{self.id} received lookup response from discovery node {message.payload[0]}')
            self.lookup_response_buffer.append(
                (message.payload[0], (message.payload[1], message.payload[2])))
            if len(self.lookup_response_buffer) >= THRESHOLD:
                print(f'{self.id} received lookup responses from all {len(self.lookup_response_buffer)} discovery nodes, processing received information.')
                self._complete_lookup()
        elif message_type == 'PING':
            sender, sender_pubkey, sender_loc = [
                x.strip() for x in crypto.decrypt(message.payload, self.privkey)[0].split('separator')]
            if self._authenticate_searcher(sender):
                print(
                    f'Searcher with ID {sender} and location {sender_loc} authenticated by searchee {self.id}')
                self.address_book[sender] = (sender_pubkey, sender_loc)
        else:
            print(message.payload)
            print(
                f'Received a regular message with payload {crypto.decrypt(message.payload, self.privkey)[0]}')

    def ping_user(self, user_id):
        payload, session_key = crypto.encrypt(
            self.id + 'separator' + str(self.pubkey) + 'separator' + self.loc, self.address_book[user_id][0])
        message = self.prepare_message(user_id, payload, 'PING')
        self.pass_message(message)

    def _authenticate_searcher(self, user_id):
        # Return True for now. Normally it will send a message encrypted with searcher’s pubkey.
        return True

    def _complete_lookup(self):
        secrets = []
        user_found_flag = True
        for response in self.lookup_response_buffer:
            discovery_node_id = response[0]
            ciphertext, nonce = response[1][0], response[1][1]
            decrypted_message = [x.strip() for x in crypto.aes_decrypt(
                self.sym_keys[discovery_node_id][0], ciphertext, nonce).split()]
            if decrypted_message[1] in set(item. name for item in ErrorCodes):
                print(f'{self.id} received error code {decrypted_message[1]}')
                user_found_flag = False
                break
            else:
                secrets.append(decrypted_message[1])
        searchee_id = decrypted_message[0]
        if user_found_flag:
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
        else:
            print(f'User {searchee_id} could not be discovered.')
            print('\n---------------------------------------------')
            print('--------------LOOKUP FAILED----------------')
            print('---------------------------------------------\n')


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
        if message.detect_type() == 'REGISTRATION':
            self._register_user(message)
        elif message.detect_type() == 'DISCOVERY':
            self._process_discovery_request(message)
        elif message.detect_type() == 'UPDATE':
            self._update_user_data(message)

    def _register_user(self, message):
        decrypted_payload, session_key = crypto.decrypt(
            message.payload, self.privkey)
        user_id, secret_piece, svk = [x.strip()
                                      for x in decrypted_payload.split(',')]
        print(
            f'Discovery node {self.id} registering user {user_id}\n')
        user_entry = UserEntry(secret_piece, svk)
        self.user_registry[user_id] = user_entry
        self.pass_message(message)

    def _process_discovery_request(self, message):
        decrypted_payload, session_key = crypto.decrypt(
            message.payload, self.privkey)
        user_id = decrypted_payload.strip()
        if user_id not in self.user_registry.keys():
            print(
                f'\nUser with ID {user_id} does not exist in discovery node {self.id}. Responding with error code {ErrorCodes.NO_USER_RECORD.name}.\n')
            ciphertext, nonce = crypto.aes_encrypt(user_id + ' ' +
                                                   ErrorCodes.NO_USER_RECORD.name, session_key)
        else:
            print(
                f'\nDiscovery node {self.id} found user with ID {user_id} in its user registry\n')
            ciphertext, nonce = crypto.aes_encrypt(user_id + ' ' +
                                                   self.user_registry[user_id].secret_piece, session_key)
        message.payload = [self.id, ciphertext[0], nonce]
        self.pass_message(message)

    def update_user_data(message):
        pass

    """
     elif message.detect_type() == 'DISCOVERY':
            asked_hash = decrypted_payload.replace(
                'discovery_flag', '').strip()
            user_found = False
            for hashes in self.user_registry.keys():
                if asked_hash in hashes:
                    ciphertext, nonce = crypto.aes_encrypt(
                        asked_hash + ' ' + self.user_registry[hashes], session_key)
                    message.payload.insert(0, [ciphertext[0], nonce])
                    print(f"User with hash {asked_hash} successfully found.")
                    user_found = True
            if not user_found:
                print(f"User with hash {asked_hash} not found.")
    """


class Message:
    def __init__(self, header, payload, type):
        self.type = MessageType[type]
        self.header = header
        self.payload = payload

    def detect_type(self):
        return self.type.name
