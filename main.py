from nodes import User
from network import Network
from const import PuddingType, N

import json


def main():
    with open('test_config.json', 'rb') as file:
        data = file.read()
        scenarios = json.loads(data)

    print(scenarios)
    for key in scenarios.keys():
        scenario = scenarios[key]
        print(scenario)
        scenario_reader(scenario)


def scenario_reader(scenario):
    pudding_type = PuddingType[scenario['pudding_type']]
    num_discovery_nodes = scenario['n']
    threshold = scenario['k']

    network = Network(
        pudding_type, num_discovery_nodes=num_discovery_nodes, threshold=threshold)

    print(type(network))
    spare_key_pairs = network.spare_key_pairs
    print(spare_key_pairs)

    scenario_actors = list()
    for user_event in scenario['user_scenario']:
        action = user_event.pop()
        actors = list()
        for actor in user_event:
            if actor not in scenario_actors or action == 'register':
                actors.append(User(network, actor, spare_key_pairs.pop()))
        execute_action(actors, action)


def execute_action(users, action):
    if action == 'register':
        users[0].register()
    elif action == 'update':
        users[0].update_user_data()
    elif action == 'discover':
        users[0].discover_user(users[1])




"""
scenario_dict = {
    'pudding_type': network_scenario[0],
    'k': network_scenario[1],
    'n': network_scenario[2],
    'user_scenario': user_scenario,
    'feasible': user_scenarios[user_scenario]
}
"""

if __name__ == "__main__":
    main()
