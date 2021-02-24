import nodes


def main():
    nodes.initiate_network(5, 10, 0)

    user_1 = nodes.User("Alice")
    user_2 = nodes.User("Bob")

    user_1.register()
    user_2.register()

    user_1.lookup_user("Bob")
    # Alice looks up a user that does not exist in the network
    user_1.lookup_user("Carol")


if __name__ == "__main__":
    main()
