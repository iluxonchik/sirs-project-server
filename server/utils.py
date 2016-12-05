"""
Utility classes and functions.
"""
import settings

from server.bluetooth.protocol import Protocol
from hashlib import pbkdf2_hmac
from base64 import b64encode, b64decode


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

def check_mac(data, mac):
    """
    Checks the message's MAC.
    """
    pass

