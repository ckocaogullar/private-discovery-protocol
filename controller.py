from nodes import User
from network import Network
from const import ErrorCodes, PuddingType, N

import json

results = dict()


def main():
    with open('test_config.json', 'rb') as file:
        data = file.read()
        scenarios = json.loads(data)

    count = 0
    print(scenarios)
    for key in scenarios.keys():
        if count == 50:
            break
        scenario = scenarios[key]
        print(scenario)
        scenario_reader(key, scenario)
        count += 1

    with open('test_results.json', 'w') as file:
        json.dump(results, file)


def scenario_reader(key, scenario):
    global resuls
    pudding_type = PuddingType[scenario['pudding_type']]
    num_discovery_nodes = scenario['n']
    threshold = scenario['k']
    feasible = scenario['feasible']

    network = Network(
        pudding_type, num_discovery_nodes=num_discovery_nodes, threshold=threshold)

    spare_key_pairs = network.spare_key_pairs

    scenario_actors = list()
    for user_event in scenario['user_scenario']:
        action = user_event.pop()
        actors = list()
        for actor in user_event:
            if actor not in scenario_actors or action == 'register':
                try:
                    actors.append(
                        User(network, actor, spare_key_pairs.pop(), spare_key_pairs.pop()))
                except:
                    print('NOT ENOUGH KEYS')
                    actors.append(User(network, actor))
        res = execute_action(actors, action)
        print(f'Result: {res}')
        result = not res
        results[key] = {
            'feasible': feasible,
            'result': result
        }


def execute_action(users, action):
    if action == 'register':
        return users[0].register()
    elif action == 'update':
        return users[0].update_user_data()
    elif action == 'discover':
        return users[0].discover_user(users[1].id)


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
