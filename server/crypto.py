"""
Contains the cryptography-related functionality of the server.
"""
import os
from enum import Enum

from os.path import basename
from cryptography.fernet import Fernet

from .exceptions import FileDoesNotExistError

class FileCryptor(object):

    class Action(Enum):
        ENCRYPT = 1
        DECRYPT = 2

    def __init__(self, key):
        # self.key = key
        self.fernet = Fernet(key=key)

    def encrypt(self, path):
        """
        Encryps the file with the specified path.

        Returns the path to the newly encrypted file.
        """
        return self._encrypt_or_decrypt_file(path, action=self.Action.ENCRYPT)

    def decrypt(self, path):
        """
        Decrypts the file with the specified path.

        Returns:
            (string) the path to the newly decrypted file.
        """
        return self._encrypt_or_decrypt_file(path, action=self.Action.DECRYPT)

    def _encrypt_or_decrypt_file(self, path, 
                                    action=Action.ENCRYPT, encoding='utf-8'):
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
