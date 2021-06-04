# Inter-project modules
from const import THRESHOLD, N

# Python modules
import json
import itertools


def main():
    # Limits
    k_values = [i for i in range(THRESHOLD)]
    n_values = [i for i in range(N)]

    scenario_combinations = list(itertools.product(k_values, n_values))

    print(scenario_combinations)

    scenarios = dict()
    for scenario in scenario_combinations:
        scenario_dict = {
            'k': scenario[0],
            'n': scenario[1]
        }
        scenario_key = '.'.join(map(str, scenario))
        scenarios[scenario_key] = scenario_dict

    with open('config.json', 'w') as file:
        json.dump(scenarios, file)


if __name__ == "__main__":
    main()
