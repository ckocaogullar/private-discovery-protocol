# Inter-project modules
from const import THRESHOLD, N, FINISH_TIME, PuddingType

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

    scenario_combinations = list(
        itertools.product(pudding_types, k_values, n_values))

    scenarios = dict()
    for scenario in scenario_combinations:
        if scenario[1] < scenario[2]:
            scenario_dict = {
                'pudding_type': scenario[0],
                'k': scenario[1],
                'n': scenario[2],
                'users': users, }
            scenario_key = '.'.join(map(str, scenario))
            scenarios[scenario_key] = scenario_dict

    user_scenarios()

    with open('config.json', 'w') as file:
        json.dump(scenarios, file)


def user_scenarios():
    solo_events = itertools.product(users, ['register', 'update'])
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
        for i in range(len(events)):
            for subset in itertools.permutations(events, i):
                if len(subset) > 0:
                    timed_events[subset] = is_feasible(subset)

        with open('scenario_combos', 'wb') as file:
            pickle.dump(timed_events, file)

    print(timed_events)


def is_feasible(event):
    # print(event)
    for e in event:
        if e[-1] != 'register':
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
