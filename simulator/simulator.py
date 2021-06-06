from src.nodes import User, Network
from src.const import PuddingType, N


def main():
    time = list()
    for n in range(1, 6):
        for k in range(1, n):
            network = Network(PuddingType.INCOGNITO, num_discovery_nodes=n, threshold=k,
                              num_relay_nodes=0, num_users=0)

            user_1 = User(network, "Alice")
            user_2 = User(network, "Bob")
            user_1.register()
            user_1.update_user_data()
            s = 'k: ' + str(k) + ' n: ' + str(n) + \
                ' time: ' + str(network.tick)
            time.append(s)
    print(time)


if __name__ == "__main__":
    main()
