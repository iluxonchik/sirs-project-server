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
DEFAULT_TOKEN_DURATION = Duration.hours(1)

# Bluetooth server settings
BT_SERVICE_UUID = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
BT_SERVICE_NAME = "SIRSService"
# maximum number of failed login attempts before the server shuts down
# setting this value to None means infinite attempts.
MAX_LOGIN_ATTEMPTS = 3
# setting below is useful for testing. If it's set to True, all bluetooth
# communications are encoded to base64 before being sent. The received BT msgs
# are also assumed to be Base64 encoded
BASE64_MODE = True  # turns base64 on/off for BluetoothRouter

# Key Storage Settings
SYM_KEY_PATH = './server/keys/sym.key'  # used in token managment
PRIV_KEY_PATH = './server/keys/priv.key'
PUB_KEY_PATH = './server/keys/pub.key'

DIR_PATH = './dir/'  # directory to be encrypted

# state file: this is how the server knows its state: wether the files
# are encrypted of decrypted. This file is encrypted with the server's
# symmetric key, so the guarantees of confidentiality and integrity are there
# 0 or something else - decrypted; 1 - encrypted
STATE_FILE = './server/state.data' 

# Test settings
TEST_BASE = './server/test/'  # include the trailing slash
DB_NAME_TEST = 'TestMe.db'
LOG_LVL_TEST = logging.DEBUG

# Bluetooth debugging settings
MOCK_DEC_ENC_KEY = False