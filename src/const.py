# Constants, enums, and data structures

import enum
from collections import namedtuple

THRESHOLD = 5
PATH_LENGTH = 3
N = 5
FINISH_TIME = 3

# Timeout values
TIMEOUT = 40

# User record data type for discovery nodes
RegistrationData = namedtuple('RegistrationData', 'secret_piece, svk')

# User record data type for other nodes
UserEntry = namedtuple('UserEntry', 'pubkey, secret_piece, auth_flag')


class ErrorCodes(enum.Enum):
    NO_USER_RECORD = 1
    USER_ALREADY_EXISTS = 2
    INVALID_SIGNATURE = 3
    INTERNAL_ID_VERIF_FAILED = 4
    NODE_NOT_AVAILABLE = 5
    TIMEOUT = 6
    EMPTY_BUFFER = 8


class SuccessCodes(enum.Enum):
    REGISTRATION_COMPLETE = 1
    UPDATE_COMPLETE = 2
    DISCOVERY_COMPLETE = 3


class MessageType(enum.Enum):
    REGISTRATION = 1
    DISCOVERY = 2
    UPDATE = 3
    PING = 4


class PuddingType(enum.Enum):
    ID_VERIFIED = 1
    INCOGNITO = 2
