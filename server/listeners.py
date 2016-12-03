from server.bluetooth.event_bus import OnBluetoothMessageListener
from server.settings import DIR_PATH, SYM_KEY_PATH
from server.crypto import FileCryptor, DirectoryCryptor
from os import walk

import logging
import abc


class BaseFileCipherListener(OnBluetoothMessageListener, metaclass=abc.ABCMeta):
    def __init__(self, key):
        self._key = key

    def update_key(self, key):
        self._key = key

    def on_message(self, msg_type, data):
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
        dc.encrypt(dirpath)        


class DirectoryDecryptorListener(BaseFileCipherListener):
    def _apply_operation(self, dc, dirpath):
        dc.decrypt(dirpath)
