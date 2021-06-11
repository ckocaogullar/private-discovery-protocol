# Inter-project modules
from src.const import THRESHOLD, N, FINISH_TIME, PuddingType

# Python modules
import json
import itertools
import pickle
import os

# Limits
k_values = [i for i in range(1, THRESHOLD+1)]
n_values = [i for i in range(1, N+1)]
time_instances = [i for i in range(0, FINISH_TIME)]
users = ['Alice', 'Bob', 'Carol']

# Pudding Types
pudding_types = ['INCOGNITO', 'ID_VERIFIED']

# Events
events = []


def main():
    all_scenarios = dict()

    network_scenarios = list(
        itertools.product(pudding_types, k_values, n_values))

    user_scenarios = prep_user_scenarios()

    count = 0
    for user_scenario in user_scenarios:
        if user_scenarios[user_scenario]:
            print(user_scenario)
            pass

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

    print(f'Number of total scenarios is {count}')
    with open('test_config.json', 'w') as file:
        json.dump(all_scenarios, file)


def prep_user_scenarios():
    solo_events = itertools.product(
        users, ['register', 'register', 'update'])
    duo_events = [x + ('discover',)
                  for x in itertools.permutations(users, 2)]
    events = list(solo_events) + duo_events
    timed_events = dict()

    if os.path.isfile('scenario_combos'):
        with open('scenario_combos', 'rb') as file:
            try:
                timed_events = pickle.load(file)
            except Exception:
                # Something has gone wrong, do not load the pickle
                print('Something has gone wrong')
                pass

    if not timed_events:
        print('New')
        for i in range(len(events)):
            print(i)
            #print(list(itertools.permutations(events, i)))
            for subset in itertools.permutations(events, i):
                if len(subset) > 0:
                    timed_events[subset] = is_feasible(subset)
                    if is_feasible(subset):
                        print(subset)
                        print('Feasible')

        with open('scenario_combos', 'wb') as file:
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
