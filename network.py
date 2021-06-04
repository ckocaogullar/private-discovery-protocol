# Inter-project modules
import nodes
from const import PuddingType

# Python modules / libraries
import os
import pickle
import inspect


class Network:
    def __init__(self, pudding_type, num_discovery_nodes=2, num_relay_nodes=10, num_users=0):
        self.discovery_nodes = list()
        self.relay_nodes = list()
        self.public_address_book = dict()
        self.public_address_book = self.initiate_network(
            num_discovery_nodes, num_relay_nodes, num_users)
        assert pudding_type in PuddingType, "Invalid Pudding type. Must be one of the following: ID_VERIFIED , INCOGNITO"
        self.pudding_type = pudding_type

    def initiate_network(self, num_discovery_nodes, num_relay_nodes, num_users):
        print('\n---------------------------------------------')
        print('------------INITIATING NETWORK---------------')
        print('---------------------------------------------\n')
        """
        Saving public - private key pairs to a list to pickle later.
        Key generation takes a lot of time. Reusing pre-generated key pairs speeds up the simulation significantly (by seconds)
        """
        key_pairs = list()
        saved_keys_flag = False
        if os.path.isfile('network_data'):
            with open('network_data', 'rb') as file:
                try:
                    key_pairs = pickle.load(file)
                    saved_keys_flag = True
                    print(key_pairs)
                except Exception:
                    # Something has gone wrong, do not load the pickle
                    print('Something has gone wrong')
                    pass

        public_address_book = dict()

        for _ in range(num_discovery_nodes):
            node = nodes.DiscoveryNode(self)
            self.assign_key_pair(node, saved_keys_flag, key_pairs)
            print(f'Discovery node created with ID {node.id}')
            self.discovery_nodes.append(node)
            public_address_book[node.id] = node

        for _ in range(num_relay_nodes):
            node = nodes.Node(self)
            self.assign_key_pair(node, saved_keys_flag, key_pairs)
            self.relay_nodes.append(node)
            print(f'Relay node created with ID {node.id}')
            public_address_book[node.id] = node

        for _ in range(num_users):
            node = nodes.User(self)
            self.assign_key_pair(node, saved_keys_flag, key_pairs)
            print(f'User created with ID {node.id}')

        for node in self.discovery_nodes:
            node.address_book = public_address_book.copy()

        for node in self.relay_nodes:
            node.address_book = public_address_book.copy()

        with open('network_data', 'wb') as file:
            pickle.dump(key_pairs, file)

        print('\n---------------------------------------------')
        print('-------------NETWORK INITIATED---------------')
        print('---------------------------------------------\n')
        return public_address_book

    def save_public_address_book(public_address_book):
        dict()
        for node in public_address_book():
            for i in inspect.getmembers(node):
                if not i[0].startswith('_'):
                    if not inspect.ismethod(i[1]):
                        print(i)

    def assign_key_pair(self, node, saved_keys_flag, key_pairs):
        if saved_keys_flag and len(key_pairs):
            key_pair = key_pairs.pop()
            node.assign_key_pair(key_pair)
        else:
            key_pair = node.assign_key_pair()
            key_pairs.append(key_pair)
