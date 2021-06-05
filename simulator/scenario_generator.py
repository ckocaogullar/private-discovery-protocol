# Inter-project modules
from src import THRESHOLD, N, FINISH_TIME, PuddingType

# Python modules
import json
import itertools
import pickle
import os

# Limits
k_values = [i for i in range(1, THRESHOLD+1)]
n_values = [i for i in range(1, N+1)]
time_instances = [i for i in range(0, FINISH_TIME)]
users = ['Alice', 'Bob']

# Pudding Types
pudding_types = ['INCOGNITO', 'ID_VERIFIED']

# Events
events = []


def main():
    prep_availability_scenarios()
    """all_scenarios = dict()

    network_scenarios = list(
        itertools.product(pudding_types, k_values, n_values))

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
    """
    all_scenarios = dict()

    network_scenarios = list(
        itertools.product(pudding_types, k_values, n_values))

    user_scenarios = prep_availability_scenarios()

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


def prep_availability_scenarios():
    solo_events = itertools.product(
        users, ['register', 'update'])
    duo_events = [x + ('discover',)
                  for x in [(users[0], users[1])]]
    events = list(solo_events) + duo_events
    print(events)
    timed_events = dict()

    if os.path.isfile('simulator/config/avail_scenario_combos'):
        with open('simulator/config/avail_scenario_combos', 'rb') as file:
            try:
                timed_events = pickle.load(file)
            except Exception:
                # Something has gone wrong, do not load the pickle
                print('Something has gone wrong')
                pass

    if not timed_events:
        for i in range(len(events)):
            for subset in itertools.permutations(events, i):
                if len(subset) > 0:
                    if is_feasible(subset):
                        timed_events[subset] = True
                        print(subset)

    print(timed_events)

    with open('simulator/config/avail_scenario_combos', 'wb') as file:
        pickle.dump(timed_events, file)

    return timed_events


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


if __name__ == "__main__":
    main()
