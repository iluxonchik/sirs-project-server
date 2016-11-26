import unittest

import base64, os, shutil, filecmp
from abc import ABCMeta

from cryptography.fernet import Fernet

from server.crypto import FileCryptor
from freezegun import freeze_time

BASE_PATH = './'  # base path for creating test files

class TestFile(object):
    """
    An object that encapsulates some uselful properties of files used in
    testing, as well as file creation.
    """
    
    def __init__(self, name, base_path='./'):
        self.name = name
        self.path = base_path + name

    def create_file(self):
        # TestFfile just encapsulates some useful file properties.
        pass

class TextTestFile(TestFile):
    """
    An object that encapsulates a text test file.
    """

    def __init__(self, name, content, base_path='./'):
        super(TextTestFile, self).__init__(name, base_path=base_path)

        f = open(self.path, mode='w+')
        f.write(content)
        f.close()

class BaseTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(BaseTestCase, self).__init__(*args, **kwargs)
        # NOTE: it's tricky to test the filename and the contents, since every
        # time the file is encrypted, the ciphertext will be different, due to
        # random IVs and the format of the token returned by Fernet:
        # Version ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC,
        # so in order to test for expected encrypted filenames and contents,
        # we have to have a fixed IV and Timestamp. To freeze the timestamp,
        # 'freezegun' module is used.
        os.urandom = FileEncryptTest._mocked_urandom
        self.key = self._get_sym_key()  # raw base64-encoded 32 byte key
        self.fernet = Fernet(self.key)

    @staticmethod
    def _mocked_urandom(n):
        return bytes(n)  # return a vector with n null bytes

    @staticmethod
    def _get_sym_key():
        return base64.b64encode(bytes('thegame'.ljust(32), encoding='ascii'))

class FileEncryptTest(BaseTestCase):

    F1_NAME = 'best_pickup_line.txt'
    F1_CONTENT = 'Would you do it if my name was Dre?' 

    @staticmethod
    def _mocked_urandom(n):
        return bytes(n)  # return a vector with n null bytes

    def setUp(self):
        self.test_files = []
        self._setup_files()        

    def tearDown(self):
        self._clear_files()

    @freeze_time("1992-12-15")
    def test_text_file_encryption(self):
        f1 = open(self.f1.path)

        # some basic sanity checks
        self.assertTrue(self.f1.path.endswith(self.F1_NAME), "unexpected " 
                                                                    "filename")
        self.assertEqual(f1.read(), self.F1_CONTENT, "unexpected file content")
        f1.close()

        expected_name = self.fernet.encrypt(self.F1_NAME.encode()).decode()
        expected_content = self.fernet.encrypt(self.F1_CONTENT.encode())

        fe = FileCryptor(key=self.key)
        ecn_file_path = fe.encrypt(path=self.f1.path)

        self.test_files.append(TestFile(name=os.path.basename(ecn_file_path)))

        self.assertEqual(BASE_PATH + expected_name, ecn_file_path, 
            'unexpected encrypted file path returned')
        
        self.assertTrue(os.path.isfile(BASE_PATH + expected_name), 
            'expected encrypted file not found')
        f1 = open(BASE_PATH + expected_name, mode='rb')
        self.assertEqual(f1.read(), expected_content, 'unexpected encrypted '
                                                                   'content')
        f1.close()

    def test_text_file_decryption(self):
        f1 = open(self.f1.path)

        # some basic sanity checks
        self.assertTrue(self.f1.path.endswith(self.F1_NAME), 'unexpected ' 
                                                                    'filename')
        self.assertEqual(f1.read(), self.F1_CONTENT, 'unexpected file content')
        f1.close()

        fe = FileCryptor(key=self.key)
        fe.encrypt(path=self.f1.path)

        encrypted_name = self.fernet.encrypt(self.F1_NAME.encode()).decode('utf-8')
        filename = fe.decrypt(BASE_PATH + encrypted_name)

        self.assertTrue(os.path.isfile(BASE_PATH + self.F1_NAME), 
            'decrypted file not found')

        f1 = open(self.f1.path)

        self.assertTrue(self.f1.path.endswith(self.F1_NAME), 'unexpected ' 
                                                        'decrypted filename')
        self.assertEqual(f1.read(), self.F1_CONTENT, 'unexpected decrypted '
                                                                'file content')
        f1.close()


    def _setup_files(self):
        """
        Sets up some basic files that will be used for testing purpuses.
        """
        self._setup_text_files()

    def _clear_files(self):
        """
        Removes the files which were created for testing purposes.
        """
        for file in self.test_files:
            try:
                os.remove(file.path)
            except:
                pass

    def _setup_text_files(self):
        """
        Sets up the text files used in texting.
        """

        self.f1 = TextTestFile(self.F1_NAME, self.F1_CONTENT, 
                                                base_path=BASE_PATH)
        self.test_files.append(self.f1)

class FileEncryptionBaseTestCase(metaclass=ABCMeta):
    """
    Abstract test class to test file encryption/decryption. To use it,
    simply inherit form this class, followied by BaseTestCase and set FILE_PATH
    variable to the path of the file you want to use for testing, for example:
    
        class EncryptImageTest(FileEncryptionBaseTestCase, BaseTestCase):
            FILE_PATH = './server/test/resources/kitten_ducks.jpg'
    """
    FILE_PATH = './server/test/resources/kitten_ducks.jpg'

    def setUp(self):
        self.test_files = []
        self._setup_files()        

    def tearDown(self):
        self._clear_files()

    def test_image_encryption_decryption(self):
        """
        Test that the image encryption-decryption works.
        """
        # Ecncrypt file
        expected_name = self.fernet.encrypt(os.path.basename(
                                        self.file_path).encode()).decode()

        fe = FileCryptor(key=self.key)
        enc_file_path = fe.encrypt(path=self.file_path)
        self.test_files.append(enc_file_path)

        # make sure that the original file was removed
        self.assertFalse(os.path.isfile(self.file_path),
                            'Non-encrypted file not removed after encryption.')

        self.assertEqual(BASE_PATH + expected_name, enc_file_path, 
            'Unexpected encrypted file path returned. '
            'Expected: {}, Actual: {}'.format(enc_file_path, 
                                                BASE_PATH + expected_name))
        
        self.assertTrue(os.path.isfile(BASE_PATH + expected_name), 
            'Expected encrypted file not found.')
        
        # TODO: test the content of the encrypted file

        # Decrypt File
        # sanity check: make sure that the non-encrypted file is not present

        orig_file_path = fe.decrypt(enc_file_path)

        self.assertTrue(os.path.isfile(self.file_path), 
            'Decrypted file not found.')
        self.assertTrue(os.path.samefile(self.file_path, orig_file_path),
            'Decrypted file does not have the expected path.')

        files_equal = filecmp.cmp(self.file_path, self.file_original_path)
        self.assertTrue(files_equal, 'Decrypted file is not equal to the '
                                                                'original one.')


    def _setup_files(self):
        self.file_original_path = self.FILE_PATH
        self.file_path = shutil.copyfile(self.FILE_PATH, 
                                                    BASE_PATH + 'test_img1.jpg')
        self.test_files.append(self.file_path)

    def _clear_files(self):
        for file in self.test_files:
            try:
                os.remove(file)
            except Exception as _:
                pass


class EncryptImageTest(FileEncryptionBaseTestCase, BaseTestCase):
    FILE_PATH = './server/test/resources/kitten_ducks.jpg' 

class EncryptMP3Test(FileEncryptionBaseTestCase, BaseTestCase):
    FILE_PATH = './server/test/resources/allegro_from_duet_in_c_major.mp3'


if __name__ == '__main__':
    unittest.main()