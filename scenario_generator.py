# Inter-project modules
from const import THRESHOLD, N, PuddingType

# Python modules
import json
import itertools


def main():
    # Limits
    k_values = [i for i in range(1, THRESHOLD)]
    n_values = [i for i in range(1, N)]
    users = ['Alice', 'Bob']

    # Pudding Types
    pudding_types = ['INCOGNITO', 'ID_VERIFIED']

    scenario_combinations = list(
        itertools.product(pudding_types, k_values, n_values))

    print(scenario_combinations)

    scenarios = dict()
    for scenario in scenario_combinations:
        scenario_dict = {
            'pudding_type': scenario[0],
            'k': scenario[1],
            'n': scenario[2]
        }
        scenario_key = '.'.join(map(str, scenario))
        scenarios[scenario_key] = scenario_dict

    with open('config.json', 'w') as file:
        json.dump(scenarios, file)


if __name__ == "__main__":
    main()
