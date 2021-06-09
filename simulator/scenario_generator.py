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
    'update': [('Alice', 'register'), ('Alice', 'update')],
    'discover': [('Alice', 'register'), ('Bob', 'register'), ('Alice', 'Bob', 'discover')],
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
                    'user_scenario': time_events[availability_scenario],
                    'time': availability_scenarios[availability_scenario][key],
                    'event_type': availability_scenario,
                    'feasible': is_feasible_time(availability_scenario, availability_scenarios[availability_scenario][key], network_scenario[1], network_scenario[2])
                }
                scenario_key = '.'.join(
                    map(str, network_scenario)) + '-' + availability_scenario + '-' + str(list(availability_scenarios[availability_scenario].keys()).index(key))
                all_scenarios[scenario_key] = scenario_dict
                count += 1
                print(count)

    with open('simulator/config/test_avail_config.json', 'w') as file:
        json.dump(all_scenarios, file)


def prep_availability_scenarios(k, n):

    timed_scenarios = dict()

    for action in time_events.keys():
        total_time = calculate_max_time(action, n, k)
        print(f'action {action}')
        print(f'total time {total_time}')
        print(f'n {n}')

        node_probs = list(itertools.product(itertools.product(
            [True, False], repeat=n), repeat=total_time))

        registration_time = [tuple([True] * n), tuple([True] * n)]

        for i in range(len(node_probs)):
            nod = node_probs[i]
            print(f'nod before modification {nod}')
            if action == 'update':
                nod = tuple(registration_time + list(nod))
            elif action == 'discover':
                nod = tuple(2 * registration_time + list(nod))
            print(f'nod after modification {nod}')
            node_probs[i] = nod

        time_probs = dict()
        for i in range(len(node_probs)):
            scenario = dict()
            for j in range(len(node_probs[i])):
                scenario[j] = node_probs[i][j]
            time_probs[i] = scenario

        timed_scenarios[action] = time_probs
        print(timed_scenarios)

    return timed_scenarios


def calculate_max_time(action, num_discovery_nodes, threshold):
    if action == 'register':
        return num_discovery_nodes
    elif action == 'discover':
        return threshold
    elif action == 'update':
        return num_discovery_nodes


def is_feasible_time(action, event, k, n):
    full_unavailable_count = 0
    for i in range(n):
        node_available_at_all = False
        for j in range(calculate_max_time(action, n, k)):
            # print(f'event[{key}] {event[key]}')
            # node_available_at_all = node_available_at_all or event[key][i]
            print(f'event[{len(event)-j-1}] {event[len(event)-j-1]}')
            node_available_at_all = node_available_at_all or event[len(
                event)-j-1][i]
        if not node_available_at_all:
            full_unavailable_count += 1
    return full_unavailable_count <= n - k


if __name__ == "__main__":
    main()
