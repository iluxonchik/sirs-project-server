"""
Contains the cryptography-related functionality of the server.
"""
import os
import logging
import time
from enum import Enum

import server.settings as settings

from server.utils import StateFileState

import os, base64

from os.path import basename

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from server.utils import Duration

from .exceptions import FileDoesNotExistError, SymKeyNotFoundError


class FileCryptor(object):

    class Action(Enum):
        ENCRYPT = 1
        DECRYPT = 2

    def __init__(self, key):
        self.fernet = Fernet(key=key)

    def encrypt(self, path, skip_filename=False):
        """
        Encryps the file with the specified path.

        Returns the path to the newly encrypted file.
        """
        logging.debug('Encrypting file {}'.format(path))
        return self._encrypt_or_decrypt_file(path, action=self.Action.ENCRYPT,
            skip_filename=skip_filename)

    def decrypt(self, path, skip_filename=False):
        """
        Decrypts the file with the specified path.

        Returns:
            (string) the path to the newly decrypted file.
        """
        logging.debug('Decrypting file {}'.format(path))
        return self._encrypt_or_decrypt_file(path, action=self.Action.DECRYPT,
            skip_filename=skip_filename)

    def _encrypt_or_decrypt_file(self, path,
                action=Action.ENCRYPT, encoding='utf-8', skip_filename=False):
        """
        Generic function which either encrypts or decrypts a file, based on the
        "action" arg.

        Args:
            action: Action.ENCRYPT or Action.DECRYPT, dependeing on wether
                you want the file to be encrypted or decrypted

        Returns:
            path (string): path of the newly encrypted or decrypted file
        """
        # NOTE: this function has been written from the encrypting perspective
        operation = (self.fernet.encrypt if action is self.Action.ENCRYPT
                     else self.fernet.decrypt)

        f = self._open_file_read(path)
        path = f.name
        plaintext = f.read()  # in a real solution might cause memory issues
        f.close()  # close and delete the original ASAP
        os.remove(path)  # remove the original, plaintext file

        # NOTE: if the server crashes mid-encryption, file loss is possible
        if skip_filename:
            logging.debug('\tSkipping filename encryption/decryption...')
            enc_file = open(path, 'wb')
        else:
            enc_file = self._encrypt_or_decrypt_filename(path, action=action)
        enc_file_path = enc_file.name

        enc_content = operation(plaintext)

        self._write_content(enc_file, enc_content)

        return enc_file_path

    def _encrypt_or_decrypt_filename(self, path,
            action=Action.DECRYPT, encoding='utf-8'):
        # NOTE: this function has been written from the encrypting perspective
        operation = (self.fernet.encrypt if action is self.Action.ENCRYPT
                     else self.fernet.decrypt)
        filename = basename(path)
        enc_filename = operation(filename.encode(encoding=encoding))
        enc_filename = enc_filename.decode(encoding=encoding)
        file_dir = os.path.dirname(path)
        new_file = open(os.path.dirname(path) + '/{}'.format(enc_filename),
                        mode='wb')
        return new_file

    def _write_content(self, file, content):
        """
        Writes the content to file as bytes. And closes the file
        """
        file.write(content)
        file.close()

    def _open_file_read(self, path):
        self._check_file_path(path)
        return open(path, mode='rb')

    def _check_file_path(self, path):
        if not os.path.isfile(path):
            raise FileDoesNotExistError('{} does not exist'.format(path))
        elif path is None:
            raise FileExistsError('None is not a valid path for a file')


class DirectoryCryptor(object):
    def __init__(self, key):
        self._fe = FileCryptor(key)
        self._sf_key = FileCryptor(base64.b64encode(open(settings.SYM_KEY_PATH, 'rb').read()))

    def encrypt(self, path):
        is_enc = self._is_state_file_encrypted()
        
        if is_enc:
            logging.warn('Tried to encrypt an already encrypted directory,'
                ' skipping encryption...')
            return

        logging.debug('Encrypting directory {}'.format(path))
        filenames = next(os.walk(path))[2]
        for file in filenames:
            self._fe.encrypt(os.path.join(path, file))

        self._write_to_state_file(StateFileState.ENCRYPTED)
        # TODO: if the content of the sate file was vaild, backup all of the
        # files in the encrypted dir


    def decrypt(self, path):
        is_dec =  not self._is_state_file_encrypted()
        
        if is_dec:
            logging.warn('Tried to decrypt an already decrypted directory,'
                ' skipping decryption...')
            return

        logging.debug('Decrypting directory {}'.format(path))
        filenames = next(os.walk(path))[2]
        for file in filenames:
            self._fe.decrypt(os.path.join(path, file))

        self._write_to_state_file(StateFileState.DECRYPTED)

    def _write_to_state_file(self, data):
        logging.debug('Writing to state file: {}'.format(data))
        state_file = open(settings.STATE_FILE, 'wb')
        state_file.write(data)
        state_file.close()
        self._sf_key.encrypt(settings.STATE_FILE, skip_filename=True)

    def _read_from_state_file(self):
        try:
            state_file = self._sf_key.decrypt(settings.STATE_FILE, 
                                                        skip_filename=True)
        except Exception:
            # error in decryption: assuming stat file is decrypted (first start)
            # let's write '0' to it -> files decrypted
            # this 'breaks' the server: you can tamper with the file and it will
            # assume it's decrypted, but you won't be able to trick the server
            # into decrypting it, so it's not as bad. We don't have a lot of
            # time for more sophisticated solutions now, so this one 'will do'.
            logging.info('Error trying to decrypt the state file, writing '
                'and returning 0 (could simply mean a fresh start).')
            data = b'0' 
            self._write_to_state_file(data)
            return data

        state_file = open(settings.STATE_FILE, 'rb')

        content = state_file.read()
        self._sf_key.encrypt(settings.STATE_FILE, skip_filename=True)
        
        return content

    def _is_state_file_encrypted(self):
        state = self._read_from_state_file()

        logging.info('State file raw content: {}'.format(state))

        if state == StateFileState.ENCRYPTED:
            logging.debug('Sate file is encrypted')
            return True
        elif state == StateFileState.DECRYPTED:
            logging.debug('Sate file is decrypted')
            return False
        else:
            logging.info('Unexpected content of state file: {}\n'.format(state) + 
                'This could simply mean that the file is uninitialized (first'
                ' start)')
            # TODO: raise an exception here, so that the files are not
            # backed up after encryption?
            return False

class TokenManager(object):
    SEPARATOR = '||'
    # username||SEPARATOR||content||iv (iv is added later)
    TOKEN_FORMAT = '{}' + SEPARATOR + '{}'

    def __init__(self, username, key=settings.SYM_KEY_PATH):
        self._username = username
        self._key_path = key

    def generate_new(self, duration=settings.DEFAULT_TOKEN_DURATION):
        """
        Generate a new token valid for 'duration' seconds.

        Token format: username||valid_until
        Returns:
            token (bytes): the generated token
        """
        plaintext_token = self.TOKEN_FORMAT.format(self._username,
                                                   int(time.time()) + duration)
        token = self._encrypt(plaintext_token)
        return token

    def check_token(self, token):
        # decrypt the token
        try:
            plain_token = self._decrypt(token)
            plain_token = plain_token.decode('utf-8')
        except Exception as e:
            # treating exceptions during decryption as invlid token.
            # For exmaple, if the sym key was changed, errors in padding
            # might occur.
            logging.info('EXCEPTION: ' + str(e))
            return False

        token_prefix = self._username + self.SEPARATOR
        if not plain_token.startswith(token_prefix):
            logging.info('Token rejected. Reason: token does not start '
                         ' with \'{}\'.'.format(token_prefix))
            return False

        token_time = plain_token[len(token_prefix):]
        token_time = int(token_time)

        is_token_valid = token_time >= int(time.time())

        if is_token_valid:
            logging.info('Token accepted.')
        else:
            logging.info('Token rejected. Reason: expired.')

        return is_token_valid

    def generate_new_sym_key(self):
        key = os.urandom(32)

        with open(self._key_path, mode='wb') as file:
            file.write(key)

    def _setup_cipher(self, iv):
        """
        All of that setup is done on purpuse. It allows to dynamically change
        the key at runtime, that's why we read the key file in every
        single time we want to generate a token.
        """
        self._iv = iv
        self.key = self._read_key()
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv),
                             backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def _encrypt(self, data, encoding='utf-8'):
        if not isinstance(data, bytes):
            data = data.encode(encoding=encoding)

        iv = os.urandom(16)
        self._setup_cipher(iv)

        padded_data = self.padder.update(data) + self.padder.finalize()
        enc_data = self.encryptor.update(
            padded_data) + self.encryptor.finalize()
        return enc_data + iv  # e(username)||e(data)||iv

    def _decrypt(self, data):
        iv = data[-16:]  # iv has fixed-length: 16 bytes
        data = data[:-16]  # strip the iv out
        self._setup_cipher(iv)
        plain_data = self.decryptor.update(data) + self.decryptor.finalize()
        plain_data = self.unpadder.update(
            plain_data) + self.unpadder.finalize()
        return plain_data

    def _read_key(self):
        if not os.path.isfile(self._key_path):
            raise SymKeyNotFoundError(
                'Key {} not found'.format(self._key_path))
        with open(self._key_path, mode='rb') as f:
            key = f.read()
        if key is None:
            raise SymKeyNotFoundError('Reading {} resulted in None'.
                                      format(self._key_path))
        return key
