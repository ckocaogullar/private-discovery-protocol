import rsa
import shamir_mnemonic as shamir
import nodes
from SSSA import sssa


def main():
    nodes.initiate_network(5, 10, 0)

    discovery_nodes = nodes.get_discovery_nodes()
    user1 = nodes.User("ceren")
    user2 = nodes.User("furkan")

   # print(user1.id, ' ', user1.pubkey)
   # print(user2.id, ' ', user1.pubkey)

    user1.register()
    user2.register()

    user1.lookup_user("furkan")
    # for i in range(len(discovery_nodes)):
    #    print(discovery_nodes[i].user_registry)


if __name__ == "__main__":
    main()
