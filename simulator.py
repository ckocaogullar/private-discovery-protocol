import nodes


def main():
    # TODO: Make this a `network = nodes.Network(num_discovery_nodes=5, num_relay_nodes=10, num_users=0)`
    nodes.initiate_network(5, 10, 0)

    # TODO: This would be come either `user_1 = nodes.User(network, "Alice")` or `user_1 = network.add_user("Alice")`
    user_1 = nodes.User("Alice")
    user_2 = nodes.User("Bob")

    user_1.register()
    user_2.register()

    user_1.lookup_user("Bob")
    # Alice looks up a user that does not exist in the network
    user_1.lookup_user("Carol")


if __name__ == "__main__":
    main()
