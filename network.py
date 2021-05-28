import nodes


class Network:
    def __init__(self, num_discovery_nodes=2, num_relay_nodes=10, num_users=0):
        self.discovery_nodes = list()
        self.relay_nodes = list()
        self.public_address_book = dict()

        print('\n---------------------------------------------')
        print('------------INITIATING NETWORK---------------')
        print('---------------------------------------------\n')
        for _ in range(num_discovery_nodes):
            node = nodes.DiscoveryNode(self)
            print(f'Discovery node created with ID {node.id}')
            self.public_address_book[node.id] = node

        for _ in range(num_relay_nodes):
            node = nodes.Node(self)
            self.relay_nodes.append(node)
            print(f'Relay node created with ID {node.id}')
            self.public_address_book[node.id] = node

        for _ in range(num_users):
            node = nodes.User(self)
            print(f'User created with ID {node.id}')

        for node in self.discovery_nodes:
            node.address_book = self.public_address_book.copy()

        for node in self.relay_nodes:
            node.address_book = self.public_address_book.copy()
        print('\n---------------------------------------------')
        print('-------------NETWORK INITIATED---------------')
        print('---------------------------------------------\n')