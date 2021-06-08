# Inter-project modules
from . import nodes
from .const import ErrorCodes, PuddingType, SuccessCodes

# Python modules / libraries
import os
import pickle
from itertools import combinations

key_pairs = list()
temp_key_pairs = list()

user_names = ['Alice', 'Bob']


class Network:
    def __init__(self, pudding_type, num_discovery_nodes=5, threshold=3, num_relay_nodes=0, num_users=0, timeout=4, avail_scenarios=None, controller=None):
        self.discovery_nodes = list()
        self.threshold = threshold
        self.relay_nodes = list()
        self.users = list()
        self.n = num_discovery_nodes
        self.spare_key_pairs = list()
        self.public_address_book = dict()
        self.public_address_book = self.initiate_network(
            num_discovery_nodes, num_relay_nodes, num_users)
        assert pudding_type in PuddingType, "Invalid Pudding type. Must be one of the following: ID_VERIFIED , INCOGNITO"
        self.pudding_type = pudding_type
        self.tick = -1
        self.timeout = timeout
        self.avail_scenarios = avail_scenarios
        self.action_success_failure = None
        self.controller = controller
        self.increment_tick()

    def initiate_network(self, num_discovery_nodes, num_relay_nodes, num_users):
        global key_pairs
        global temp_key_pairs
        print('\n---------------------------------------------')
        print('------------INITIATING NETWORK---------------')
        print('---------------------------------------------\n')
        """
        Saving public - private key pairs to a list to pickle later.
        Key generation takes a lot of time. Reusing pre-generated key pairs speeds up the simulation significantly (by seconds)
        """

        saved_keys_flag = False
        if os.path.isfile('network_data'):
            with open('network_data', 'rb') as file:
                try:
                    key_pairs = pickle.load(file)
                    temp_key_pairs = key_pairs.copy()
                    saved_keys_flag = True
                except Exception:
                    # Something has gone wrong, do not load the pickle
                    print('Something has gone wrong')
                    pass

        public_address_book = dict()

        for _ in range(num_discovery_nodes):
            node = nodes.DiscoveryNode(self)
            self.assign_key_pair(node, saved_keys_flag)
            print(f'Discovery node created with ID {node.id}')
            self.discovery_nodes.append(node)
            public_address_book[node.id] = node

        for _ in range(num_relay_nodes):
            node = nodes.Node(self)
            self.assign_key_pair(node, saved_keys_flag)
            self.relay_nodes.append(node)
            print(f'Relay node created with ID {node.id}')
            public_address_book[node.id] = node

        for _ in range(num_users):
            node = nodes.User(
                self, 'Alice', temp_key_pairs.pop(), temp_key_pairs.pop())
            self.assign_key_pair(node, saved_keys_flag)

            print(f'User created with ID {node.id}')

        for node in self.discovery_nodes:
            node.address_book = public_address_book.copy()

        for node in self.relay_nodes:
            node.address_book = public_address_book.copy()

        self.discovery_node_combinations = [list(l) for l in list(combinations(
            self.discovery_nodes, self.threshold))]
        for comb in self.discovery_node_combinations:
            comb.sort(key=lambda x: x.id)

        self.spare_key_pairs = temp_key_pairs.copy()

        # Return some spare key pairs for the controller to use if it needs to create users

        with open('network_data', 'wb') as file:
            pickle.dump(key_pairs, file)

        print('\n---------------------------------------------')
        print('-------------NETWORK INITIATED---------------')
        print('---------------------------------------------\n')
        return public_address_book

    def assign_key_pair(self, node, saved_keys_flag):
        global key_pairs
        global temp_key_pairs
        if saved_keys_flag and len(temp_key_pairs):
            key_pair = temp_key_pairs.pop()
            node.assign_key_pair(key_pair)
        else:
            key_pair = node.assign_key_pair()
            key_pairs.append(key_pair)

    def increment_tick(self):
        self.tick += 1
        print(f'network tick is {self.tick}')
        if self.tick > self.timeout and self.action_success_failure != SuccessCodes.REGISTRATION_COMPLETE:
            print(f'User found timeout')
            self.action_success_failure = ErrorCodes.TIMEOUT
        else:
            for user in self.users:
                if user.registration_complete_flag:
                    print('User registration complete')
                    self.action_success_failure = SuccessCodes.REGISTRATION_COMPLETE
        if self.avail_scenarios:
            print(f'self.avail_scenarios {self.avail_scenarios}')
            for key in self.avail_scenarios:
                if int(key) * 2 == self.tick:
                    print(
                        f'Adjusting availability of {len(self.avail_scenarios[key])} nodes {self.avail_scenarios[key]}')
                    for i in range(len(self.avail_scenarios[key])):
                        if self.avail_scenarios[key][i]:
                            self.discovery_nodes[i].make_available()
                        else:
                            self.discovery_nodes[i].make_unavailable()
            if self.tick == self.timeout and self.action_success_failure == None:
                print('doing the extra bit')
                for i in range(len(self.avail_scenarios[key])):
                    if self.avail_scenarios[str(len(self.avail_scenarios)-1)][i]:
                        self.discovery_nodes[i].make_available()
                    else:
                        self.discovery_nodes[i].make_unavailable()

        return self.tick