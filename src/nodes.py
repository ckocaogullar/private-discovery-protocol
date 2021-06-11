"""
Anonymous Student
University of Cambridge
MPhil in Advanced Computer Science Project 2020-2021
Simulation Tool for Privacy-Preserving User Discovery in Anonymous Communication Networks
"""

# Python modules
import random
import string
import copy

# Inter-project modules
from .network import Network
from .const import PATH_LENGTH,  UserEntry, RegistrationData, ErrorCodes, SuccessCodes, MessageType, PuddingType
from . import crypto
import math

from Crypto.Util import number

from src import network

"""
Representing time with an event-driven tick-based approach
Every tick, one of the following happens: a message is passed, or a message is processed
"""


class Node:
    def __init__(self, network):
        # Pseudorandom strings as Node ID and location
        self.network = network
        self.address_book = network.public_address_book.copy()
        while True:
            self.id = ''.join(random.SystemRandom().choice(
                string.ascii_uppercase + string.digits) for _ in range(4))
            if self.id not in list(self.network.public_address_book.keys()):
                break
        self.loc = ''.join(random.SystemRandom().choice(
            string.ascii_uppercase + string.digits) for _ in range(4))

        self.pubkey = None
        self.privkey = None
        self.message_on_hold = None

    def assign_key_pair(self, key_pair=None):
        # Public - private key pair for encrypting all communications
        if key_pair:
            self.pubkey, self.privkey = key_pair
            return key_pair
        else:
            self.pubkey, self.privkey = crypto.generate_key_pair()
            return (self.pubkey, self.privkey)

    def pass_message(self, message, next_hop):
        next_hop_found = False
        print(f'Node {self.id} passing message with header {message.header}')
        if self.message_on_hold:
            print(f'Self message on hold with header {message.header}')
        else:
            for key in copy.deepcopy(list(self.address_book.keys())):
                if next_hop in key:
                    print(
                        f'Message is in {self.id}, next stop is {self.address_book[key].id}.')
                    self.address_book[key].process_message(message)

                    if len(message.header) != 0 and not self.address_book[key].message_on_hold:
                        result = self.address_book[key].pass_message(
                            message, message.header.pop())

                    next_hop_found = True
            if not next_hop_found:
                print(
                    f'{self.id} does not know node {next_hop}, dropping the message.')
            # self.network.increment_tick()

    def process_message(self, message):
        # Need this declaration for overloading
        pass

    def prepare_message(self, target, payload, type, anonymous=False, handle=None):
        if len(self.network.relay_nodes):
            if len(self.network.relay_nodes) >= PATH_LENGTH * 2:
                selected_relay_nodes = random.sample(
                    self.network.relay_nodes, k=PATH_LENGTH * 2)
            else:
                selected_relay_nodes = self.network.relay_nodes
        else:
            selected_relay_nodes = []
        path = [target] + selected_relay_nodes[PATH_LENGTH:]
        if anonymous:
            if handle:
                self_address = handle
            else:
                self_address = self.id
            path = [self_address] + selected_relay_nodes[:PATH_LENGTH] + path
        header = [x.id if isinstance(x, Node) else x for x in path]
        print(f'Prepared message with header {header}')
        return Message(header, payload, type)

    def update_address_book(self, key, node):
        self.address_book[key] = node


class User(Node):
    def __init__(self, *args):
        # Input checks
        assert 0 < len(
            args) <= 4, "User constructor can only be called with 1 - 3 parameters: Network, [(User ID) or none], [(key_pair) or none]."
        assert isinstance(
            args[0], Network), "The user must take network as the first parameter."
        super().__init__(args[0])
        if len(args) >= 2:
            assert isinstance(
                args[1], str), "Only strings are allowed as user IDs."
            self.id = args[1]
        if len(args) == 3:
            assert isinstance(
                args[2], tuple), "Only tuples are allowed as user key pair."
            self.assign_key_pair(args[2])
        else:
            self.assign_key_pair()

        self.registration_complete_flag = False
        self.update_complete_flag = False
        self.discovery_complete_flag = False

        # A buffer for received discovery responses. This list consists of elements that are tuples of type (discovery_node_id, response_message)
        self.discovery_response_buffer = list()

        # A buffer for received registration responses. This list consists of elements that are tuples of type discovery_node_id
        self.registration_response_buffer = list()

        # A buffer for received update responses. This list consists of elements that are tuples of type discovery_node_id
        self.update_response_buffer = list()

        # Digital signature public verification key (svk), private signing key pair (ssk)

        self.handles = self.id + ' '
        self.secret = None
        self.secret_pieces = None
        self.svk, self.ssk = crypto.generate_key_pair()
        self.network.users.append(self)
        self.message_buffer = list()

        print(f'User created with ID {self.id} and location {self.loc}')

    def send_message_from_buffer(self):
        try:
            message = self.message_buffer.pop(0)
            print(
                f'{self.id} sending message from buffer. {len(self.message_buffer)} messages left in buffer: {[x.type for x in self.message_buffer]}')
            self.pass_message(message, message.header.pop())
            print('calling increment tick here')
            self.network.increment_tick()
        except IndexError:
            print(f'No messages left in user {self.id}`s message buffer.')
            return 'empty'

    def request_registration(self):
        # Send registration request to a randomly selected discovery server
        selected_discovery_server = random.choice(self.network.discovery_nodes)
        selected_discovery_servers = random.sample(
            self.network.discovery_nodes, self.network.threshold)

        return selected_discovery_server.initiate_registration(self, selected_discovery_servers)

    """
    Registration and update in both Pudding protocols are very similar on the user's side
    This function is used for registration by default and optionally for user data updates
    Possible values for the flag are REGISTRATION and UPDATE
    """

    def register(self, flag='REGISTRATION'):
        assert flag == 'REGISTRATION' or flag == 'UPDATE', 'registration() can only take REGISTRATION and UPDATE as the flag'
        # Split the secret (user ID and network location) into n pieces

        # User's contact information is their secret. Padding the value for secret sharing.
        secret = self.pubkey + b' --USER_LOC-- ' + \
            bytes(self.loc, encoding='utf-8')
        self.secret = secret if (len(secret) % 2 == 0) else secret + b' '

        # Dividing secret into secret shares
        self.secret_pieces = crypto.divide_secret(
            self.secret, self.network.threshold, self.network.n)

        if self.network.pudding_type == PuddingType.ID_VERIFIED:
            result = self._register_id_verified(flag)
        elif self.network.pudding_type == PuddingType.INCOGNITO:
            result = self._register_incognito(flag)


    def discover_user(self, user_id):
        print('\n---------------------------------------------')
        print('--------------STARTING DISCOVERY----------------')
        print('---------------------------------------------\n')
        print(
            f'Searcher with ID {self.id} is discovering searchee with ID {user_id}')
        selected_discovery_nodes = copy.deepcopy(self.network.discovery_nodes)
        self.sym_keys = dict()
        salts = dict()
        salted_hashes = dict()
        if self.network.pudding_type == PuddingType.ID_VERIFIED:
            discovery_message = user_id
            for discovery_node in selected_discovery_nodes:
                encrypted_discovery_msg, session_key = crypto.encrypt(
                    discovery_message, discovery_node.pubkey)
                nonce = encrypted_discovery_msg[1]
                self.sym_keys[discovery_node.id] = (session_key, nonce)
                payload = encrypted_discovery_msg
                message = self.prepare_message(
                    discovery_node, payload, 'DISCOVERY', anonymous=True)
                self.message_buffer.append(message)
        elif self.network.pudding_type == PuddingType.INCOGNITO:
            selected_discovery_nodes.sort(key=lambda x: x.id)
            for discovery_node in selected_discovery_nodes:
                salts[discovery_node.id] = crypto.oprf(discovery_node, user_id)
            for discovery_node in selected_discovery_nodes:
                print(f'salts {salts}')
                salts_without_node = copy.deepcopy(
                    salts)
                if len(salts_without_node) > 0:
                    salts_without_node.pop(discovery_node.id)
                    k_random_salts = random.sample(
                        list(salts_without_node.keys()), self.network.threshold - 1)
                    k_random_salts.append(discovery_node.id)
                    k_random_salts.sort()
                    salts_for_hashing = [salts[x] for x in k_random_salts]
                else:
                    salts_for_hashing = [salts[discovery_node.id]]
                print(f'salts_without_node {salts_without_node}')
                salted_hashes[discovery_node.id] = crypto.hash_with_salts(
                    salts_for_hashing, user_id)
                encrypted_discovery_msg, session_key = crypto.encrypt(
                    salted_hashes[discovery_node.id], discovery_node.pubkey)
                nonce = encrypted_discovery_msg[1]
                self.sym_keys[discovery_node.id] = (session_key, nonce)
                payload = encrypted_discovery_msg
                message = self.prepare_message(
                    discovery_node, payload, 'DISCOVERY', anonymous=True)
                self.message_buffer.append(message)

        self.network.increment_tick()

    def update_user_data(self):
        """
        Generates a new secret, signs the public key, updates it on discovery nodes.
        This is a demonstration of the authorised user data update feature.
        This feature can be generalised to other user data.
        """
        # User's contact information is their secret. Padding the value for secret sharing.
        secret = self.pubkey + b' --USER_LOC-- ' + \
            bytes(self.loc, encoding='utf-8')
        self.secret = secret if (len(secret) % 2 == 0) else secret + b' '

        # Dividing secret into secret shares
        self.secret_pieces = crypto.divide_secret(
            self.secret, self.network.threshold, self.network.n)

        self.assign_key_pair()
        return self.register('UPDATE')

    def process_message(self, message):
        message_type = message.detect_type()
        if message_type == 'DISCOVERY':
            self._process_discovery_message(message)
        elif message_type == 'PING':
            self._process_ping(message)
        elif message_type == 'REGISTRATION':
            self._process_registration_response(message)
        elif message_type == 'UPDATE':
            self._process_update_response(message)
        else:
            print(
                f'Received a regular message with payload {crypto.decrypt(message.payload, self.privkey)[0]}')

    def ping_user(self, user_id):
        payload, session_key = crypto.encrypt(
            self.id + 'separator' + self.pubkey.decode('utf-8') + 'separator' + self.loc, self.address_book[user_id][0])
        message = self.prepare_message(user_id, payload, 'PING')
        self.message_buffer.append(message)

    def _process_registration_response(self, message):
        print(
            f'{self.id} received registration response')
        self.registration_response_buffer.append(message.payload[0])
        print(f'götütütütütü {len(self.registration_response_buffer)}')
        if (len(self.registration_response_buffer) >= self.network.n and self.network.tested_event_type != 'register') or (len(self.registration_response_buffer) >= self.network.threshold and self.network.tested_event_type == 'register'):
            print(f'{self.id} received registration responses from {len(self.registration_response_buffer)} discovery nodes, registration complete.')
            self.registration_complete_flag = SuccessCodes.REGISTRATION_COMPLETE

    def _process_update_response(self, message):
        print(
            f'{self.id} received update response')
        self.update_response_buffer.append(message.payload[0])
        if len(self.update_response_buffer) >= self.network.threshold:
            print(f'{self.id} received update responses from {len(self.update_response_buffer)} discovery nodes, update complete.')
            self.update_complete_flag = SuccessCodes.UPDATE_COMPLETE

    def _register_id_verified(self, flag):
        if self.request_registration():
            # Make yourself known to relay nodes
            for relay_node in self.network.relay_nodes:
                relay_node.update_address_book(self.id, self)

            self.network.public_address_book[self.id] = self

            # Register to discovery nodes
            for discovery_node in self.network.discovery_nodes.copy():
                secret_piece = self.secret_pieces.pop()

                if flag == 'UPDATE':
                    signature = crypto.sign(self.ssk, secret_piece)
                    signature = str(number.bytes_to_long(signature))

                svk_or_signature = (
                    self.svk).decode('utf-8') if flag == 'REGISTRATION' else signature
                registration_message = self.id + '--SEP--' + \
                    secret_piece + '--SEP--' + svk_or_signature
                d_pubkey = discovery_node.pubkey
                encrypted_registration_msg = crypto.encrypt(
                    registration_message, d_pubkey)[0]
                payload = encrypted_registration_msg
                message = self.prepare_message(
                    discovery_node, payload, flag, anonymous=True)
                self.message_buffer.append(message)
            self.network.increment_tick()

    def _register_incognito(self, flag):
        salt_dict = dict()

        # Get pseudorandom salt values using OPRF for the registering user's ID
        for discovery_node in self.network.discovery_nodes:
            salt_dict[discovery_node] = crypto.oprf(
                discovery_node, self.id)
        """
        Prepare salted hashes for each discovery server.

        Each discovery server D receives (THRESHOLD-1)-combination-of-all-discovery-servers-many hash values per user.
        These hashes are used as keys to find the user's secret piece stored in that discovery server.
        Each of these hashes use salts of one THRESHOLD-combination-of-all-discovery-servers that include D.
        """
        for discovery_node in self.network.discovery_nodes:
            registration_message = ''
            combinations_with_discovery_node = [
                x for x in self.network.discovery_node_combinations if discovery_node in x]
            assert len([x for x in combinations_with_discovery_node if discovery_node not in x]
                       ) == 0, "Discovery node combinations are picked wrong for the discovery servers"
            assert int(math.factorial(len(self.network.discovery_nodes) - 1) / (math.factorial(self.network.threshold - 1) * math.factorial(
                len(self.network.discovery_nodes) - self.network.threshold))) == len(combinations_with_discovery_node), "Number of picked combinations is off"
            print(f'{self.id} registering to discovery node {discovery_node.id}')
            print(
                f'combinations_with_discovery_node {combinations_with_discovery_node}')
            for comb in combinations_with_discovery_node:
                print(
                    f'{self.id} registering to node {discovery_node.id} with combination {[x.id for x in comb]} and salts {[salt_dict[d] for d in comb]}')
                handle = crypto.hash_with_salts(
                    [salt_dict[d] for d in comb], self.id)
                registration_message += handle + ' '
                if handle not in self.handles:
                    self.handles += handle + ' '

                print(f'{self.id} adding self to network with handle {handle}')
                self.network.public_address_book[handle] = self

            secret_piece = self.secret_pieces.pop()

            if flag == 'UPDATE':
                signature = crypto.sign(self.ssk, secret_piece)
                signature = str(number.bytes_to_long(signature))

            svk_or_signature = (self.svk).decode(
                'utf-8') if flag == 'REGISTRATION' else signature
            registration_message += '--SEP--' + secret_piece + '--SEP--' + svk_or_signature

            encrypted_registration_msg = crypto.encrypt(
                registration_message, discovery_node.pubkey)[0]
            payload = encrypted_registration_msg
            self_address = None
            if len(self.network.relay_nodes):
                self_address = self.id
            else:
                self_address = handle
            message = self.prepare_message(
                discovery_node, payload, flag, anonymous=True, handle=self_address)
            self.message_buffer.append(message)

        # Make yourself known to relay nodes
        for relay_node in self.network.relay_nodes:
            relay_node.update_address_book(self.handles, self)

        self.network.increment_tick()

    def _authenticate_searcher(self, user_id, sender_pubkey, sender_loc):
        self.discover_user(user_id)
        return str(self.address_book[user_id].pubkey) == sender_pubkey

    def _process_discovery_message(self, message):
        print(
            f'{self.id} received discovery response')
        try:
            self.discovery_response_buffer.append(
                (message.payload[0], (message.payload[1], message.payload[2])))
        except:
            print('The discovery response is an error. Not adding to the buffer')
        if len(self.discovery_response_buffer) >= self.network.threshold:
            print(f'self.network.threshold {self.network.threshold}')
            print(f'{self.id} received discovery responses from all {len(self.discovery_response_buffer)} discovery nodes, processing received information.')
            self._complete_discovery()

    def _process_ping(self, message):
        sender, sender_pubkey, sender_loc = [
            x.strip() for x in crypto.decrypt(message.payload, self.privkey)[0].split('separator')]
        self.address_book[sender] = UserEntry(sender, sender_pubkey, False)
        print(
            f'Initiating internal authentication: {self.id} discovering {sender}')
        if self._authenticate_searcher(sender, sender_pubkey, sender_loc):
            print(
                f'Searcher with ID {sender} authenticated by searchee {self.id}')
        else:
            self.address_book[sender] = UserEntry(sender, sender_pubkey, False)
            print(
                f'Internal authentication for searcher with ID {sender} has failed.')

    def _complete_discovery(self):
        secrets = []
        for response in self.discovery_response_buffer:
            if ErrorCodes.NO_USER_RECORD in response:
                print(f'{self.id} received error code {response.payload}')
                self.discovery_complete_flag = ErrorCodes.NO_USER_RECORD
                print(f'User could not be discovered.')
                print('\n---------------------------------------------')
                print('--------------DISCOVERY FAILED----------------')
                print('---------------------------------------------\n')
                return ErrorCodes.NO_USER_RECORD
            discovery_node_id = response[0]
            ciphertext, nonce = response[1][0], response[1][1]
            decrypted_message = [x.strip() for x in crypto.aes_decrypt(
                self.sym_keys[discovery_node_id][0], ciphertext, nonce).split()]
            secrets.append(decrypted_message[1])
        searchee_id = decrypted_message[0]

        combined_secret = crypto.combine_secret(
            secrets).split(' --USER_LOC-- ')
        searchee_pubkey = combined_secret[0].strip()
        searchee_loc = combined_secret[1].strip()
        print(
            f'\n{self.id} completed their discovery for {searchee_id}. Adding to the address book.')
        new_user = not searchee_id in self.address_book.keys()
        self.address_book[searchee_id] = UserEntry(
            searchee_pubkey, searchee_loc, True)
        self.discovery_complete_flag = True
        print('\n---------------------------------------------')
        print('--------------DISCOVERY COMPLETED----------------')
        print('---------------------------------------------\n')
        if new_user:
            print(f'{self.id} pinging {searchee_id}')


class DiscoveryNode(Node):

    def __init__(self, network):
        super().__init__(network)
        self.user_registry = dict()
        self.oprf_key = str(random.randint(math.pow(2, 8), math.pow(2, 16)))
        self.available = True

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
        print(
            f'Discovery node {self.id} processing message with header {message.header}')
        if self.available:
            if message.detect_type() == 'REGISTRATION':
                self._register_user(message)
            elif message.detect_type() == 'DISCOVERY':
                self._process_discovery_request(message)
            elif message.detect_type() == 'UPDATE':
                self._update_user_data(message)
        else:
            print(
                f'Discovery node {self.id} is unavailable. Network status {self.network.action_success_failure}')
            if self.network.action_success_failure == ErrorCodes.TIMEOUT or self.network.is_complete_success():
                return
            elif not self.message_on_hold:
                print('Putting message on hold')
                self.message_on_hold = message

    def _register_user(self, message):
        decrypted_payload, session_key = crypto.decrypt(
            message.payload, self.privkey)

        # If Pudding type is ID-Verified, user_registry_key is the User ID. If it is Incognito, it is a set of salted hashes
        user_registry_key, secret_piece, svk = [x.strip()
                                                for x in decrypted_payload.split('--SEP--')]

        print(
            f'Discovery node {self.id} registering user with handle {user_registry_key}\n')
        user_entry = RegistrationData(secret_piece, svk)
        if user_registry_key not in self.user_registry.keys():
            self.user_registry[user_registry_key] = user_entry
            for key in [x.strip() for x in user_registry_key.split()]:
                self.address_book[key] = self.network.public_address_book[key]
        else:
            print(
                f'\nUser entry with ID/handle {user_registry_key} already exists in discovery node {self.id}. Responding with error code {ErrorCodes.USER_ALREADY_EXISTS.name}.\n')
            return ErrorCodes.USER_ALREADY_EXISTS
        print(f'Message header here is {message.header}')
        if not self.message_on_hold:
            self.pass_message(message, message.header.pop())

    def _process_discovery_request(self, message):
        decrypted_payload, session_key = crypto.decrypt(
            message.payload, self.privkey)

        # If Pudding type is ID-Verified, user_registry_key is the User ID. If it is Incognito, it is a salted hash
        asked_key = decrypted_payload.strip()
        user_registry_key = asked_key
        user_found = False
        if self.network.pudding_type == PuddingType.ID_VERIFIED:
            user_found = asked_key in self.user_registry.keys()

        elif self.network.pudding_type == PuddingType.INCOGNITO:
            for hashes in self.user_registry.keys():
                if asked_key in hashes:
                    user_found = True
                    user_registry_key = hashes
                    break

        if user_found:
            print(
                f'\nDiscovery node {self.id} found user with ID / handle {user_registry_key} in its user registry\n')
            ciphertext, nonce = crypto.aes_encrypt(asked_key + ' ' +
                                                   self.user_registry[user_registry_key].secret_piece, session_key)
            message.payload = [self.id, ciphertext[0], nonce]

        else:
            print(
                f'\nUser with ID/handle {user_registry_key} does not exist in discovery node {self.id}. Responding with error code {ErrorCodes.NO_USER_RECORD.name}.\n')
            ciphertext, nonce = crypto.aes_encrypt(user_registry_key + ' ' +
                                                   ErrorCodes.NO_USER_RECORD.name, session_key)
            message.payload = ErrorCodes.NO_USER_RECORD
            return ErrorCodes.NO_USER_RECORD

        if not self.message_on_hold:
            self.pass_message(message, message.header.pop())

    def _update_user_data(self, message):
        decrypted_payload, session_key = crypto.decrypt(
            message.payload, self.privkey)

        # If Pudding type is ID-Verified, user_registry_key is the User ID. If it is Incognito, it is a set of salted hashes
        user_registry_key, secret_piece, signature = [x.strip()
                                                      for x in decrypted_payload.split('--SEP--')]
        print(
            f'Discovery node {self.id} received update request from user with ID / handle {user_registry_key}\n')
        try:
            user_svk = self.user_registry[user_registry_key].svk
        except KeyError:
            print(
                f'\nUser with ID/handle {user_registry_key} does not exist in discovery node {self.id}. Responding with error code {ErrorCodes.NO_USER_RECORD.name}.\n')
            ciphertext, nonce = crypto.aes_encrypt(user_registry_key + ' ' +
                                                   ErrorCodes.NO_USER_RECORD.name, session_key)
            return ErrorCodes.NO_USER_RECORD

        signature = number.long_to_bytes(int(signature))

        verified = crypto.verify(bytes(user_svk, encoding='utf-8'),
                                 signature, secret_piece)
        if verified:
            print(f'User data is updated.')
        else:
            print(
                f'Signature verification failed. Responding with error code {ErrorCodes.INVALID_SIGNATURE.name}')
            return ErrorCodes.INVALID_SIGNATURE
        user_entry = RegistrationData(secret_piece, user_svk)
        self.user_registry[user_registry_key] = user_entry

        if not self.message_on_hold:
            self.pass_message(message, message.header.pop())

    def make_unavailable(self):
        print(f'Discovery node {self.id} is unavailable')
        self.available = False
        #self.pass_message(self.message_on_hold, '--DUMMY--')

    def make_available(self):
        print(f'Discovery node {self.id} is available')
        self.available = True
        if self.message_on_hold:
            message = self.message_on_hold
            self.message_on_hold = None
            self.process_message(message)


class Message:
    def __init__(self, header, payload, type):
        self.type = MessageType[type]
        self.header = header
        self.payload = payload

    def detect_type(self):
        return self.type.name
