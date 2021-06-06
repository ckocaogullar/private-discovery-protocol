# Inter-project modules
from src import THRESHOLD, N, FINISH_TIME, PuddingType

# Python modules
import json
import itertools
import pickle
import os
import string

# Limits
k_values = [i for i in range(1, 3)]
n_values = [i for i in range(1, 3)]
time_instances = [i for i in range(0, FINISH_TIME)]
users = ['Alice', 'Bob']

# Pudding Types
pudding_types = ['INCOGNITO', 'ID_VERIFIED']

# Events
events = []

# Time events
time_events = {
    'register': [('Alice', 'register')],
    # 'update': [('Alice', 'register'), ('Alice', 'update')],
    # 'discover': [('Alice', 'register'), ('Bob', 'register'), ('Alice', 'Bob', 'discover')],
}


def main():
    # prep_availability_scenarios()
    all_scenarios = dict()

    # This is wrong. Must be k <= n at all times
    all_network_scenarios = list(
        itertools.product(pudding_types, k_values, n_values))

    network_scenarios = list()
    print(network_scenarios)
    for scenario in all_network_scenarios:
        if scenario[1] <= scenario[2]:
            network_scenarios.append(scenario)

    print(network_scenarios)
    """
    user_scenarios = prep_user_scenarios()

    count = 0
    for user_scenario in user_scenarios:
        if user_scenarios[user_scenario]:
            print(user_scenario)

        for network_scenario in network_scenarios:
            if network_scenario[1] <= network_scenario[2]:
                scenario_dict = {
                    'pudding_type': network_scenario[0],
                    'k': network_scenario[1],
                    'n': network_scenario[2],
                    'user_scenario': user_scenario,
                    'feasible': user_scenarios[user_scenario]
                }
                scenario_key = '.'.join(
                    map(str, network_scenario)) + '-' + str(list(user_scenarios.keys()).index(user_scenario))
                all_scenarios[scenario_key] = scenario_dict
                count += 1
        if count >= 200:
            break

    all_scenarios = dict()
    """

    count = 0
    for network_scenario in network_scenarios:
        print(f'net sc {network_scenario}')
        availability_scenarios = prep_availability_scenarios(
            network_scenario[1], network_scenario[2])

        for availability_scenario in availability_scenarios:
            for key in availability_scenarios[availability_scenario]:
                scenario_dict = {
                    'pudding_type': network_scenario[0],
                    'k': network_scenario[1],
                    'n': network_scenario[2],
                    'user_scenario': availability_scenario,
                    'time': availability_scenarios[availability_scenario][key],
                    'feasible': is_feasible_time(availability_scenarios[availability_scenario][key], network_scenario[1], network_scenario[2])
                }
                scenario_key = '.'.join(
                    map(str, network_scenario)) + '-' + availability_scenario + '-' + str(list(availability_scenarios[availability_scenario].keys()).index(key))
                all_scenarios[scenario_key] = scenario_dict
                count += 1
                print(count)

    # if count >= 200:
    #    break

    with open('simulator/config/test_avail_config.json', 'w') as file:
        json.dump(all_scenarios, file)


def prep_user_scenarios():
    solo_events = itertools.product(
        users, ['register', 'register', 'update'])
    duo_events = [x + ('discover',)
                  for x in itertools.permutations(users, 2)]
    events = list(solo_events) + duo_events
    scenarios = dict()

    if os.path.isfile('scenario_combos'):
        with open('../config/scenario_combos', 'rb') as file:
            try:
                scenarios = pickle.load(file)
            except Exception:
                # Something has gone wrong, do not load the pickle
                print('Something has gone wrong')
                pass

    if not scenarios:
        for i in range(len(events)):
            for subset in itertools.permutations(events, i):
                if len(subset) > 0:
                    scenarios[subset] = is_feasible(subset)
                    if is_feasible(subset):
                        print(subset)
                        print('Feasible')

        with open('../config/scenario_combos', 'wb') as file:
            pickle.dump(scenarios, file)

    return scenarios


def prep_availability_scenarios(k, n):

    timed_scenarios = dict()

    for action in time_events.keys():
        total_time = calculate_max_time(action, n, k)
        print(f'action {action}')
        print(f'total time {total_time}')
        print(f'n {n}')

        node_probs = list(itertools.product(itertools.product(
            [True, False], repeat=n), repeat=total_time))

        for nod in node_probs:
            print(nod)

        time_probs = dict()
        for i in range(len(node_probs)):
            scenario = dict()
            for j in range(total_time):
                scenario[j] = node_probs[i][j]
            time_probs[i] = scenario

        timed_scenarios[action] = time_probs
        print(timed_scenarios)

    with open('simulator/config/avail_scenario_combos', 'wb') as file:
        pickle.dump(timed_scenarios, file)

    return timed_scenarios


def calculate_max_time(action, num_discovery_nodes, threshold):
    if action == 'register':
        return num_discovery_nodes
    elif action == 'discover':
        return 2 * (num_discovery_nodes + threshold)
    elif action == 'update':
        return 2 * num_discovery_nodes


def is_feasible(event):
    # print(event)
    for e in event:
        if e[-1] == 'register':
            for inst in e[:-1]:
                if event.count((inst, 'register')) == 2:
                    return False
        elif e[-1] != 'register':
            for inst in e[:-1]:
                if (inst, 'register') not in event:
                    # print('False')
                    return False
                elif event.index((inst, 'register')) > event.index(e):
                    # print('False')
                    return False
    return True


def is_feasible_time(event, k, n):
    full_unavailable_count = 0
    for key in event:
        if not any(event[key]):
            full_unavailable_count += 1
    return full_unavailable_count <= n - k


if __name__ == "__main__":
    main()
