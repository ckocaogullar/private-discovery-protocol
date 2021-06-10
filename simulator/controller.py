
from src.const import ErrorCodes, SuccessCodes
from src import User, Network, PuddingType

import json
import copy


results = dict()


def main():
    prot_liveness()


def prot_liveness():
    with open('simulator/config/test_avail_config_new_working.json', 'rb') as file:
        data = file.read()
        scenarios = json.loads(data)

    print(len(scenarios.keys()))
    # with open('simulator/config/test_avail_results.json', 'w') as file:
    #     for key in scenarios:
    #         print('\n------------------------------------------------------------------')
    #         print(f'Scenario name {key}')
    #         liveness_scenario_reader(key, scenarios[key])
    #     json.dump(results, file)

    # single_scenario = "ID_VERIFIED.1.3-register-310"
    # liveness_scenario_reader(single_scenario,
    #                          scenarios[single_scenario])


# Scenario name ID_VERIFIED.1.3-register-310

def liveness_scenario_reader(key, scenario, trial_count=0):
    global results
    num_trials = trial_count
    scenario_copy = copy.deepcopy(scenario)
    pudding_type = PuddingType[scenario['pudding_type']]
    num_discovery_nodes = scenario['n']
    threshold = scenario['k']
    feasible = scenario['feasible']
    event_type = scenario['event_type']

    network = Network(
        pudding_type, num_discovery_nodes=num_discovery_nodes, num_relay_nodes=1, threshold=threshold, timeout=len(scenario['time'])*4, avail_scenarios=scenario['time'], tested_event_type=event_type)
    print('Created network')
    print(f'event_type {event_type}')
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
    elif network.action_success_failure == SuccessCodes.REGISTRATION_COMPLETE and event_type == 'register':
        result = True
    elif network.action_success_failure == SuccessCodes.UPDATE_COMPLETE and event_type == 'update':
        result = True
    elif network.action_success_failure == SuccessCodes.DISCOVERY_COMPLETE and event_type == 'discover':
        result = True
    else:
        result = None
    print(f'Result: {result}')
    results[key] = {
        'feasible': feasible,
        'result': result
    }
    # Try again, max. of three times
    if result != feasible:
        if num_trials < 3:
            num_trials += 1
            print('Something unexpected happened, trying scenario again\n')
            liveness_scenario_reader(key, scenario_copy, num_trials)
        else:
            assert result == feasible, 'Result and feasibility are not the same'
    else:
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
