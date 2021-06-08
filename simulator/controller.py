
from src.const import ErrorCodes, SuccessCodes
from src import User, Network, PuddingType

import json
import enum

results = dict()


def main():
    prot_liveness()


def prot_correctness():
    max_tick = -1
    with open('simulator/config/test_config.json', 'rb') as file:
        data = file.read()
        scenarios = json.loads(data)

    count = 0
    print(scenarios)
    for key in scenarios:
        # if count == 50:
        #    break
        scenario = scenarios[key]
        print(scenario)
        tick = correctness_scenario_reader(key, scenario)
        max_tick = tick if tick > max_tick else tick
        count += 1

    print(f'Max network tick is {max_tick}')
    with open('simulator/config/test_results.json', 'w') as file:
        json.dump(results, file)


def prot_liveness():
    with open('simulator/config/test_avail_config.json', 'rb') as file:
        data = file.read()
        scenarios = json.loads(data)

    for key in scenarios:
        liveness_scenario_reader(key, scenarios[key])

    with open('simulator/config/test_avail_results.json', 'w') as file:
        json.dump(results, file)


def liveness_scenario_reader(key, scenario):
    global results
    pudding_type = PuddingType[scenario['pudding_type']]
    num_discovery_nodes = scenario['n']
    threshold = scenario['k']
    feasible = scenario['feasible']

    network = Network(
        pudding_type, num_discovery_nodes=num_discovery_nodes, threshold=threshold, timeout=num_discovery_nodes*len(scenario['time'])*2, avail_scenarios=scenario['time'])

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
        execute_action(actors, action)
        if network.action_success_failure == ErrorCodes.TIMEOUT:
            result = False
        elif network.action_success_failure == SuccessCodes.REGISTRATION_COMPLETE:
            result = True
        else:
            result = None
        results[key] = {
            'feasible': feasible,
            'result': result
        }
    return network.tick


def correctness_scenario_reader(key, scenario):
    global results
    pudding_type = PuddingType[scenario['pudding_type']]
    num_discovery_nodes = scenario['n']
    threshold = scenario['k']
    feasible = scenario['feasible']

    network = Network(
        pudding_type, num_discovery_nodes=num_discovery_nodes, threshold=threshold, controller=self)

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
        execute_action(actors, action)
        if network.action_success_failure == ErrorCodes.TIMEOUT:
            result = False
        elif network.action_success_failure == SuccessCodes.REGISTRATION_COMPLETE:
            result = True
        else:
            result = None
        results[key] = {
            'feasible': feasible,
            'result': result
        }
    return network.tick


def execute_action(users, action):
    if action == 'register':
        users[0].register()
    elif action == 'update':
        users[0].update_user_data()
    elif action == 'discover':
        users[0].discover_user(users[1].id)


if __name__ == "__main__":
    main()
