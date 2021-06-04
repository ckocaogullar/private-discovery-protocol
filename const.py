# Constants, enums, and data structures

import enum
from collections import namedtuple

THRESHOLD = 3
PATH_LENGTH = 3
N = 5

# Timeout values
REGISTRATION_TIMEOUT = 10
REGISTRATION_TIMEOUT = 10

# User record data type for discovery nodes
RegistrationData = namedtuple('RegistrationData', 'secret_piece, svk')

# User record data type for other nodes
UserEntry = namedtuple('UserEntry', 'pubkey, secret_piece, auth_flag')


class ErrorCodes(enum.Enum):
    NO_USER_RECORD = 1
    NODE_NOT_AVAILABLE = 2


class MessageType(enum.Enum):
    REGISTRATION = 1
    DISCOVERY = 2
    UPDATE = 3
    PING = 4


class PuddingType(enum.Enum):
    ID_VERIFIED = 1
    INCOGNITO = 2
