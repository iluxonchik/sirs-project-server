"""
Utility classes and functions.
"""
import settings

from server.bluetooth.protocol import Protocol
from hashlib import pbkdf2_hmac
from base64 import b64encode, b64decode

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import hmac, hashlib, logging

class Duration(object):
    MINUTE = 60  # a minute is 60 seconds
    HOUR = MINUTE * 60  # an hour is 60 minutes
    DAY = HOUR * 24  # a day is 24 hours
    
    @classmethod
    def minutes(cls, seconds):
        return seconds * cls.MINUTE
    
    @classmethod
    def hours(cls, seconds):
        return seconds * cls.HOUR

    @classmethod
    def days(cls, seconds):
        return seconds * cls.DAY

class StateFileState(object):
    DECRYPTED = b'0'
    ENCRYPTED = b'1'

def derive_decryption_key(login_pwd, salt):
    """
    Derive decryption key from the received password.
    """
    return b64encode(pbkdf2_hmac('sha256', login_pwd, salt,
                                                        settings.PBKDF2_RNDS))

def derive_pwd_hash_from_decryption_key(dec_key, salt):
    return b64encode(pbkdf2_hmac('sha256', dec_key, salt, 1))

def derive_pwd_hash_from_login(login_pwd, salt):
    dec_key = b64decode(derive_decryption_key(login_pwd, salt))
    h = derive_pwd_hash_from_decryption_key(dec_key, salt)
    return h


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

def encrypt_data(data, key, iv, encoding='utf-8'):
    if not isinstance(data, bytes):
        data = data.encode(encoding=encoding)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
    padder = padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()
    padded_data = padder.update(data) + padder.finalize()
    enc_data = encryptor.update(padded_data) + encryptor.finalize()

    return enc_data

def decrypt_data(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
    unpadder = padding.PKCS7(128).unpadder()
    decryptor = cipher.decryptor()
    plain_data = decryptor.update(data) + decryptor.finalize()
    plain_data = unpadder.update(plain_data) + unpadder.finalize()
    
    return plain_data

def check_mac(key, data, iv, mac):
    """
    Checks the message's MAC.

    MAC = HMAC-SHA256(data||iv)
    """
    msg = data + iv
    expected_hash = compute_mac(key, data, iv)
    # NOTE: provides protection from timing attacks (read docs)
    is_valid = hmac.compare_digest(expected_hash, mac)

    if is_valid:
        logging.debug('\tMAC check successful')
    else:
        logging.warn('\tMAC check failed. Expected: {}\n'
            'Actual: {}'.format(expected_hash, mac))
    
    return is_valid

def compute_mac(key, data, iv):
    """
    Computes HMAC-SHA256(data||iv).
    """
    mac = hmac.new(key, msg=data+iv, digestmod=hashlib.sha256)
    return mac.digest()

