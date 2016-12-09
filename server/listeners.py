from server.user import User
from server.bluetooth.event_bus import OnBluetoothMessageListener
from server.settings import DIR_PATH, SYM_KEY_PATH
from server.crypto import FileCryptor, DirectoryCryptor
from os import walk
from server.bluetooth.protocol import Protocol
from server.exceptions import NoUserRegisteredError

from server.utils import (derive_decryption_key,
    derive_pwd_hash_from_decryption_key, derive_pwd_hash_from_login)

import logging, sys, base64
import abc

import server.settings as settings
from hashlib import pbkdf2_hmac


class BaseFileCipherListener(OnBluetoothMessageListener, metaclass=abc.ABCMeta):
    def __init__(self, cli_sock, router, internal_enc):
        self._router = router
        self._key = None
        self._cli_sock = cli_sock
        self._internal_enc = internal_enc

    def on_message(self, msg_type, data):
        """
        Message data is: username||pbkdf2_of_pwd||token||token_len.
            token_len is always 3 bytes.
        Token checks are done in BlueRouter.
        """
        # TODO: REMOVE "if"! TEST CODE.
        # TEST MOCK
        data_len = len(data)

        # last 3 bytes of the message indicate the token size
        token_len = int(data[data_len - 3:])
        data = data[:data_len - 3]
        data_len = data_len - 3  # 3 bytes have been stripped off the data
        logging.debug('\ttoken_len: {}'.format(token_len))


        # extreact token
        token = data[data_len - token_len:]
        logging.debug('\ttoken: {}'.format(token))
        data = data[:data_len - token_len]
        data_len = data_len - token_len  # data changed, update its len
        
        interm_key = data[data_len - 32:]  # interm key is always 256 bit
        logging.debug('\tinterm_key: {}, len: {}'.format(interm_key, 
                                                            len(interm_key)))
        salt = data[:data_len - 32]  # username
        logging.debug('\tsalt(username): {}'.format(salt))

        # let's check if the token is valid
        u = User(salt.decode('utf-8'))
        is_token_valid = u.token_manger.check_token(token)
        
        if not is_token_valid:
            logging.info('Token rejected at listener!')
            self._router.send(Protocol.TOKEN_WRONG_ERR)
            return

        logging.debug('Intermediate key: {}'.format(interm_key))
        logging.debug('Salt: {}'.format(salt))

        # TODO: REMOVE! TEST CODE.
        # TEST MOCK
        if settings.MOCK_DEC_ENC_KEY:
            logging.warn('MOCKING deryption/encryption key '
                                        '(settings.MOCK_DEC_ENC_KEY = True)')
            interm_key = b'password pbkdf2 received from msg'
            salt = b'username obtained from msg'

        self._key = derive_decryption_key(interm_key, salt)
        self._internal_enc.key = self._key

        logging.info(
            'Will start encrypting/decrypting '
            'files with key: {}'.format(self._key))
        dc = DirectoryCryptor(self._key)
        self._apply_operation(dc, DIR_PATH)

    @abc.abstractmethod
    def _apply_operation(self, dc, dirpath):
        """
        Either encrypts or decrypts a directory.
        """
        pass


class DirectoryEncryptorListener(BaseFileCipherListener):
    def _apply_operation(self, dc, dirpath):
        logging.info('Encrypting directory {}'.format(dirpath))
        dc.encrypt(dirpath)


class DirectoryDecryptorListener(BaseFileCipherListener):
    def _apply_operation(self, dc, dirpath):
        logging.info('Decrypting directory {}'.format(dirpath))
        dc.decrypt(dirpath)

class InternalDirectoryEncryptorListner(OnBluetoothMessageListener):
    def __init__(self, key=None):
        self.key = None

    def on_message(self, msg_type, data):
        if  self.key is not None:
            logging.info('Internal request for encryption success.')
            dc = DirectoryCryptor(self.key)
            dc.encrypt(DIR_PATH)
        else:
            logging.error('Internal request for encryption FAILED! Reason:'
                ' self.key is None. FILES NOT ENCRYPTED!')


class UserPasswordAuthListener(OnBluetoothMessageListener):
    """
    Receive user password auth request, then either send "login failed"
    msg or send back a newly genreated token.
    """

    def __init__(self, router, internal_enc):
        self._router = router
        self._failed_logins = 0
        self._internal_enc = internal_enc

    def on_message(self, msg_type, data):
        """
        data: username||pwd
        """
        data_len = len(data)
        pwd = data[data_len - 32:]
        username = data[:data_len - 32]
        
        logging.debug( 'UserPasswordAuthListener received username: {}, '
            'password: {}'.format(username, pwd))

        decryption_key = base64.b64decode(derive_decryption_key(pwd, username))
        pwd = derive_pwd_hash_from_decryption_key(decryption_key, username)

        username = username.decode(encoding='utf-8')
        user = User(username)
        try:
            login_success = user.password_auth(pwd)
            if login_success:
                # generate a new token and send it
                logging.debug('Login success')
                new_token = user.token_manger.generate_new()
                self._router.send(Protocol.NEW_TOKEN, new_token)
                self._failed_logins = 0
                self._internal_enc.key = base64.b64encode(decryption_key)
            else:
                # wrong user or pass
                logging.debug('Login error: wrong username or password')
                self._router.send(Protocol.PWD_LOGIN_ERR)
                self._trigger_failed_login()
        except NoUserRegisteredError:
            logging.debug('Login error: no user found in database')
            self._router.send(Protocol.NO_USER_ERR)
            self._trigger_failed_login()

    def _trigger_failed_login(self):
        if settings.MAX_LOGIN_ATTEMPTS is not None:
            self._failed_logins = self._failed_logins + 1
            if self._failed_logins > settings.MAX_LOGIN_ATTEMPTS:
                logging.info('{} failed login attempts, sever shutting down...'.
                    format(self._failed_logins))
                sys.exit(0)