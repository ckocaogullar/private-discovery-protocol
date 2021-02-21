import rsa
import shamir_mnemonic as shamir
import nodes
from SSSA import sssa


def main():
    for i in range(5):
        nodes.DiscoveryNode()

    discovery_nodes = nodes.get_discovery_nodes()
    user1 = nodes.User()
    user2 = nodes.User("ck596")

   # print(user1.id, ' ', user1.pubkey)
   # print(user2.id, ' ', user1.pubkey)

    user1.register()
    user2.register()
    for i in range(len(discovery_nodes)):
        print(discovery_nodes[i].get_user_registry())


if __name__ == "__main__":
    main()
