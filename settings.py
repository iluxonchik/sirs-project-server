"""
Server settings.
"""
import logging

LOG_LVL = logging.DEBUG  # log level in app

# DB Settings
DB_NAME = 'TheDocumentary.db'
DB_USER_TABLE = 'user'

# Crypto settings
PBKDF2_RNDS = 100000  # server-side PBKDF2 rounds

# Key Storage Settings
SYM_KEY_PATH = './server/keys/sym.key'

# Test settings
TEST_BASE = './server/test/'  # include the trailing slash
DB_NAME_TEST = 'TestMe.db'
LOG_LVL_TEST = logging.DEBUG