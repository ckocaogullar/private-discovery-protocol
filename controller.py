from nodes import User
from network import Network
from const import PuddingType, N


def main():
    network = Network(PuddingType.INCOGNITO, num_discovery_nodes=N,
                      num_relay_nodes=10, num_users=0)

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
