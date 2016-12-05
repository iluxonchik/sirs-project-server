from server.bluetooth.event_bus import OnBluetoothMessageListener
from server.settings import DIR_PATH, SYM_KEY_PATH
from server.crypto import FileCryptor, DirectoryCryptor
from os import walk
from server.bluetooth.protocol import Protocol

from server.utils import derive_decryption_key

import logging
import abc

import server.settings as settings
from hashlib import pbkdf2_hmac


class BaseFileCipherListener(OnBluetoothMessageListener, metaclass=abc.ABCMeta):
    def __init__(self, cli_sock, router):
        self._router = router
        self._key = None
        self._cli_sock = cli_sock

    def on_message(self, msg_type, data):
        """
        Message data is: username||pbkdf2_of_pwd 
        Token checks are done in BlueRouter.
        """
        # TODO: REMOVE "if"! TEST CODE.
        # TEST MOCK
        if not settings.MOCK_DEC_ENC_KEY:
            if data is None:
                logging.error('Encryption/Decrytion listener '
                                                    'received \'None\' data')
            data_len = len(data)
            interm_key = data[data_len - 32:]  # interm key is always 256 biy
            salt = data[:data_len-32]
            logging.debug('Intermediate key: {}'.format(interm_key))
            logging.debug('Salt: {}'.format(salt))

        # TODO: REMOVE! TEST CODE.
        # TEST MOCK
        if settings.MOCK_DEC_ENC_KEY:
            interm_key = b'password pbkdf2 received from msg'
            salt = b'username obtained from msg'

        self._key = derive_decryption_key(interm_key, salt)

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

class UserPasswordAuthListener(OnBluetoothMessageListener):
    """
    Receive user password auth request, then either send "login failed"
    msg or send back a newly genreated token.
    """
    pass

