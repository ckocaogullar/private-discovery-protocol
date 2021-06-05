
from src.const import ErrorCodes
from src import User, Network, PuddingType

import json

results = dict()


def main():
    max_tick = -1
    with open('simulator/config/test_avail_config.json', 'rb') as file:
        data = file.read()
        scenarios = json.loads(data)

    count = 0
    print(scenarios)
    for key in scenarios.keys():
        # if count == 50:
        #    break
        scenario = scenarios[key]
        print(scenario)
        tick = scenario_reader(key, scenario)
        max_tick = tick if tick > max_tick else tick
        count += 1

    print(f'Max network tick is {max_tick}')
    with open('simulator/config/test_avail_results.json', 'w') as file:
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

    scenario_actors = dict()
    for user_event in scenario['user_scenario']:
        print(f'scenario is {user_event}')
        action = user_event.pop()
        actors = list()
        for actor in user_event:
            if actor not in scenario_actors.keys() or action == 'register':
                try:
                    user = User(network, actor, spare_key_pairs.pop())
                except:
                    print('NOT ENOUGH KEYS')
                    user = User(network, actor)
                scenario_actors[actor] = user
            actors.append(scenario_actors[actor])
        res = execute_action(actors, action)
        result = not res
        results[key] = {
            'feasible': feasible,
            'result': result
        }
    return network.tick


def execute_action(users, action):
    if action == 'register':
        return users[0].register()
    elif action == 'update':
        return users[0].update_user_data()
    elif action == 'discover':
        return users[0].discover_user(users[1].id)


if __name__ == "__main__":
    main()
