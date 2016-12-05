"""
Server settings.
"""
import logging

from server.utils import Duration

LOG_LVL = logging.DEBUG  # log level in app

# DB Settings
DB_NAME = 'TheDocumentary.db'
DB_USER_TABLE = 'user'

# Crypto settings
PBKDF2_RNDS = 100000  # server-side PBKDF2 rounds

# Token Settings
DEFAULT_TOKEN_DURATION = Duration.minutes(1)

# Bluetooth server settings
BT_SERVICE_UUID = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
BT_SERVICE_NAME = "SIRSService"

# Key Storage Settings
SYM_KEY_PATH = './server/keys/sym.key'  # used in token managment
PRIV_KEY_PATH = './server/keys/priv.key'
PUB_KEY_PATH = './server/keys/pub.key'

DIR_PATH = './dir/'  # directory to be encrypted

# Test settings
TEST_BASE = './server/test/'  # include the trailing slash
DB_NAME_TEST = 'TestMe.db'
LOG_LVL_TEST = logging.DEBUG

# Bluetooth debugging settings
MOCK_DEC_ENC_KEY = True