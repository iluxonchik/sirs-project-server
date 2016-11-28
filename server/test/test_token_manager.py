import unittest
import settings
import time

import os

from server.crypto import TokenManager
from server.utils import Duration

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class TokenManagerTestCase(unittest.TestCase):

    def setUp(self):
        self.iv = os.urandom(16)
        self.key = os.urandom(32)
        self._setup_cipher()
        self.orig_time_func = time.time
        self.orig_urandom = os.urandom

        settings.SYM_KEY_PATH = settings.TEST_BASE + 'sym.key'

        with open(settings.SYM_KEY_PATH, mode='wb') as file:
            file.write(self.key)

    def tearDown(self):
        self._unfreeze_time()  # "catch-all"
        os.urandom = self.orig_urandom
        os.remove(settings.SYM_KEY_PATH)


    def test_token_generation(self):
        self._freeze_time()

        tm = TokenManager(username='TheDocumentary', key=settings.SYM_KEY_PATH)
        self.iv = tm._iv 

        # gen a token valid for 1 minute
        token = tm.generate_new(duration=Duration.minutes(1))

        token_format = TokenManager.TOKEN_FORMAT.format('TheDocumentary', 
                                            time.time() + Duration.minutes(1))

        expected_token = self._encrypt(token_format)

        self._unfreeze_time()
        self.assertEqual(token, expected_token, 'Unexpected generated token')
        self.assertTrue(tm.check_token(token), 'Valid token refused')

    def test_invalid_token(self):
        tm = TokenManager(username='TheDocumentary', key=settings.SYM_KEY_PATH)
        invalid_token = b'You would do it if my name was Dre?'
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(tm._iv),
            backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        invalid_token = padder.update(invalid_token) + padder.finalize()
        invalid_token = encryptor.update(invalid_token) + encryptor.finalize()

        self.assertFalse(tm.check_token(invalid_token), 
            'Invalid token accepted')

    def test_expired_token(self):
        self._freeze_time()

        tm = TokenManager(username='TheDocumentary', key=settings.SYM_KEY_PATH)
        # gen a token valid for 1 minute
        token = tm.generate_new(duration=Duration.minutes(1))

        self.assertTrue(tm.check_token(token))  # sanity check
        curr_time = time.time()
        time.time = lambda: curr_time + 61  # mock 1 min 1 sec passed

        self.assertFalse(tm.check_token(token), 'Expired token not rejected')
        self._unfreeze_time()

    def test_new_sym_key_generation(self):
        os.urandom = lambda x: b'Still Dre day'

        with open(settings.SYM_KEY_PATH, mode='rb') as f:
            f_content = f.read()
        self.assertNotEqual(f_content, os.urandom(32))
        
        tm = TokenManager(username='TheDoctorsAdvocate', 
                                                key=settings.SYM_KEY_PATH)
        tm.generate_new_sym_key()

        with open(settings.SYM_KEY_PATH, mode='rb') as f:
            f_content = f.read()
        self.assertEqual(f_content, os.urandom(32))
        
        os.urandom = self.orig_urandom

    def test_token_invalid_after_new_sym_key_genrated(self):
        self._freeze_time()

        tm = TokenManager(username='TheDocumentary', key=settings.SYM_KEY_PATH)
        self.iv = tm._iv 

        # gen a token valid for 1 minute
        token = tm.generate_new(duration=Duration.minutes(1))

        self._unfreeze_time()
        tm.generate_new_sym_key()
        self.assertFalse(tm.check_token(token), 'Invalid token accepted.')
        

    def _freeze_time(self):
        # okay, let's mock out the time function
        curr_time = time.time()
        time.time = lambda: int(curr_time)

    def _unfreeze_time(self):
        time.time = self.orig_time_func

    def _setup_cipher(self):
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv),
            backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def _encrypt(self, data, encoding='utf-8'):
        self._setup_cipher()
        if not isinstance(data, bytes):
            data = data.encode(encoding=encoding)

        padded_data = self.padder.update(data) + self.padder.finalize()
        enc_data = self.encryptor.update(padded_data) + self.encryptor.finalize()
        return enc_data

    def _decrypt(self, data):
        self._setup_cipher()
        plain_data = self.decryptor.update(data) + self.decryptor.finalize()
        plain_data = self.unpadder.update(plain_data) + self.unpadder.finalize()
        return plain_data



if __name__ == '__main__':
    unittest.main()