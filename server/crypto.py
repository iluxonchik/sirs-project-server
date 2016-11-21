"""
Contains the cryptography-related functionality of the server.
"""
import os

from os.path import basename
from cryptography.fernet import Fernet

from .exceptions import FileDoesNotExistError

class FileCryptor(object):
    def __init__(self, key):
        self.key = key

    def encrypt(self, path):
        """
        Encryps the file with the specified path.

        Returns the path to the newly encrypted file.
        """
        f = self._open_file_read(path)
        path = f.name
        plaintext = f.read()  # in a real solution might cause memory issues
        f.close()  # close and delete the original ASAP
        os.remove(path)  # remove the original, plaintext file

        # NOTE: if the server crashes mid-encryption, file loss is possible

        fernet = Fernet(self.key)
        enc_file = self._encrypt_filename(path, fernet)
        enc_file_path = enc_file.name

        enc_content = fernet.encrypt(plaintext)

        self._write_enc_content(enc_file, enc_content)

        return enc_file_path

    def decrypt(self, path):
        """
        Decrypts the file with the specified path.

        Returns:
            (string) the path to the newly decrypted file.
        """
        f = self._open_file_read(path)
        path = f.name
        plaintext = f.read()  # in a real solution might cause memory issues
        f.close()  # close and delete the original ASAP
        os.remove(path)  # remove the original, plaintext file

        # NOTE: if the server crashes mid-encryption, file loss is possible

        fernet = Fernet(self.key)
        dec_file = self._decrypt_filename(path, fernet)
        dec_file_path = dec_file.name

        dec_content = fernet.decrypt(plaintext)

        self._write_enc_content(dec_file, dec_content)

        return dec_file_path


    def _encrypt_filename(self, path, fernet, encoding='utf-8'):
        """
        Encrypts the filename of the provded file, creates a new file with the
        encrypted filename and returns that file.

        The returned file is open in mode 'wb' (write bytes).
        """
        filename = basename(path)
        enc_filename = fernet.encrypt(filename.encode(encoding=encoding))
        enc_filename = enc_filename.decode(encoding=encoding)
        file_dir = os.path.dirname(path)
        new_file = open(os.path.dirname(path) + '/{}'.format(enc_filename), mode='wb')
        return new_file 

    def _decrypt_filename(self, path, fernet, encoding='utf-8'):
            """
            Encrypts the filename of the provded file, creates a new file with the
            encrypted filename and returns that file.

            The returned file is open in mode 'wb' (write bytes).
            """
            filename = basename(path)
            enc_filename = fernet.decrypt(filename.encode(encoding=encoding))
            enc_filename = enc_filename.decode(encoding=encoding)
            file_dir = os.path.dirname(path)
            new_file = open(os.path.dirname(path) + '/{}'.format(enc_filename), mode='wb')
            return new_file

    def _write_enc_content(self, file, content):
        """
        Writes the encrypted content to file as bytes. And closes the file
        """
        file.write(content)
        file.close()


    def _open_file_read(self, path):
        self._check_file_path(path)
        return open(path, mode='rb')

    # def _open_file_write(self, path):
    #     self._check_file_path(path)
    #     return open(path, mode='w')

    def _check_file_path(self, path):
        if not os.path.isfile(path):
            raise FileDoesNotExistError('{} does not exist'.format(path))
        elif path is None:
            raise FileExistsError('None is not a valid path for a file')
