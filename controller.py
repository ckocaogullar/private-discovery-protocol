from nodes import User
from network import Network
from const import PuddingType, N

import json


def main():
    with open('config.json', 'rb') as file:
        data = file.read()
        scenarios = json.loads(data)

    print(scenarios)
    for key in scenarios.keys():
        scenario = scenarios[key]
        print(scenario)
        network = Network(PuddingType[scenario['pudding_type']], num_discovery_nodes=scenario['n'], threshold=scenario['k'],
                          num_relay_nodes=0, num_users=0)

        user_1 = User(network, "Alice")
        user_2 = User(network, "Bob")

        user_1.register()
        # user_2.register()

        # user_1.discover_user("Bob")
        user_1.update_user_data()
        # Alice looks up a user that does not exist in the network
        # user_1.lookup_user("Carol")
        print(network.tick)


if __name__ == "__main__":
    main()
