# Constants, enums, and data structures

import enum
from collections import namedtuple

THRESHOLD = 3
PATH_LENGTH = 3

UserEntry = namedtuple('UserEntry', 'secret_piece, svk')


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
