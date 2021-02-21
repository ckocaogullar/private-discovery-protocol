# Ceren Kocaoğullar, ck596
# University of Cambridge
# MPhil in Advanced Computer Science Project 2020-2021
# Simulation for A Private Node Discovery Protocol for Anonymous Networks

import rsa
import shamir_mnemonic as shamir
import uuid
import random
from SSSA import sssa

discovery_nodes = list()
threshold = 3
sss = sssa()


class Node:
    def __init__(self):
        (pubkey, privkey) = rsa.newkeys(256)
        self.pubkey = pubkey
        self.privkey = privkey
        self.id = str(uuid.uuid4())
        self.loc = str(uuid.uuid4())


class User(Node):
    #print(sss.combine([secrets[0], secrets[1], secrets[3]]))
    global sss
    global discovery_nodes

    def __init__(self, *args):
        super().__init__()
        secret = bytes(str(self.pubkey.n) + ' ' +
                       str(self.pubkey.e) + ' ' + self.loc, encoding='utf-8')
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
        secret_pieces = sss.create(threshold, n, self.secret)
        print(secret_pieces)
        if self.request_registration():
            for i in range(n):
                d_pubkey = discovery_nodes[i].pubkey
                encrypted_registration_message = rsa.encrypt(
                    bytes(secret_pieces[i], encoding='utf-8'), d_pubkey)
                discovery_nodes[i].register(encrypted_registration_message)

    def _divide_secret(self, secret, k, n):
        # TODO: Shamir's secret sharing

        #secret_pieces = sss.create(k, n, self.secret)
        # print(secret_pieces)
        return list(map(str, random.sample(range(0, 100), n)))


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
        message = rsa.decrypt(encrypted_message, self.privkey).decode('utf8')
        user_id = str(message).split(',')[0].strip()
        secret_piece = str(message).split(',')[1].strip()
        self.user_registry[user_id] = secret_piece


def get_discovery_nodes():
    global discovery_nodes
    return discovery_nodes
