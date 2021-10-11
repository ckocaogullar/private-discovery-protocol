# Simulator for A Private Discovery Protocol for Anonymity Systems

This simulator functions as a model checker for the two protocols that I have created as my dissertation for the MPhil in Advanced Computer Science degree at the University of Cambridge. [Here](https://github.com/ckocaogullar15/private-discovery-protocol/blob/main/dissertation.pdf) is a link to the dissertation. Detailed information of everything described here can be found in that document.

## Problem Statement

Private communications have recently become an integral part of our everyday lives with encrypted messaging applications such as Signal, Telegram, and WhatsApp. On the other hand, PGP, a twenty-year-old encryption system mostly used for email, has historically seen limited adoption. A likely explanation for this disparity is that finding friends on messaging apps is easy via using phone numbers, whereas it is obscure and confusing on PGP, as demonstrated by research.

Despite having a practical user discovery mechanism and protecting message con- tents, encrypted messaging apps do not provide metadata privacy. Therefore, they potentially expose critical information about conversations and jeopardise user privacy. Anonymous communication networks can solve this problem. How- ever, similar to PGP, the current user discovery mechanisms for these networks are unusable.

## Overview of the Protocols
I have established two security protocols, each representing a different point in the usability-privacy tradeoff space: ID-Verified Pudding allows user discovery through validated email addresses, but it cannot hide usernames from the user discovery mechanism. Incognito Pudding solves this issue at the cost of sacrificing the ability to link Pudding usernames to well-known external names. 

## Structure and Running of the Simulator
The main objective of this simulator is to demonstrate the practicality of the two Pudding protocols by testing their liveness and completeness with a model checking approach. This simulator checks the [correctness](https://github.com/ckocaogullar15/private-discovery-protocol/tree/correctness-tests) and [liveness](https://github.com/ckocaogullar15/private-discovery-protocol/tree/liveness-tests) properties of the proposed protocols, code for those maintained in different branches. 

The developed simulation tool tests the core protocol functionalities, i.e. registra- tion, discovery, and user data update, in a comprehensive set of scenarios. To cover scenarios with all possible state configurations in a determined state space, I implemented a scenario generator, which can be run with the command from the main folder of the project:

```
python3 -m simulator.scenario_generator
```

To test the generated scenarios, you should run the command:

```
python3 -m simulator.controller
```

With its current variable configurations, the simulator tests all possible protocol runs in a total of 44,572 scenarios. The protocols behave as expected in all of them. Putting the full logic of the protocol into action through this tool, it is apparent that in a large number of scenarios, both Pudding protocols are realistic and functional.
