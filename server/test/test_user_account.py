import unittest

import settings
from settings import TEST_BASE

import os, glob, sqlite3, logging

from server.user import User
from server.exceptions import NoUserRegisteredError

from hashlib import pbkdf2_hmac

class UserAccountTestCase(unittest.TestCase):
    def setUp(self):
        settings.DB_NAME = TEST_BASE + settings.DB_NAME_TEST

    def tearDown(self):
        self._remove_db_files()

    def _remove_db_files(self):
        for f in glob.glob('{}*'.format(settings.DB_NAME)):
            os.remove(f)

    def test_no_account_auth(self):
        """
        Make sure that an exception is raised in case of a login attempt
        when there is no active account in the system.
        """
        user = User(username='Dr.Dre')
        
        with self.assertRaises(NoUserRegisteredError):
            # NOTE: password is the decryption key, internally, another
            # PBKDF2 interation is done to check against the hash
            user.password_auth(password='Still Dre')
        
        with self.assertRaises(NoUserRegisteredError):
            user.token_auth(token='Dre Day')

    def test_password_auth(self):
        user = User(username='TheGame')  # creates a DB
        pwd = pbkdf2_hmac('sha256', b'The Protege Of The D.R.E.', 
                                                            b'TheGame', 10)

        # insert user into DB
        conn = sqlite3.connect(settings.DB_NAME)
        conn.execute('INSERT INTO user VALUES(?, ?)', (user.username, pwd))
        conn.commit()

        self.assertTrue(user.password_auth(pwd))

    def test_user_register(self):
        user = User('Dr.Dre')
        pwd = pbkdf2_hmac('sha256', b'The Chronic', b'Dr.Dre', 4)

        user.register(pwd)
        self.assertTrue(user.password_auth(pwd), 'User login after registration'
            ' failed.')
        
        conn = sqlite3.connect(settings.DB_NAME)

        res = conn.execute('SELECT * FROM user')
        self.assertEqual(len(res.fetchall()), 1)

        res = conn.execute('SELECT * FROM user WHERE username=? AND password=?',
            ('Dr.Dre', pwd))
        self.assertEqual(len(res.fetchall()), 1)

    def test_user_update_password(self):
        user = User('Dr.Dre')
        pwd = pbkdf2_hmac('sha256', b'2001', b'Dr.Dre', 2)

        user.register(pwd)
        new_pwd = pbkdf2_hmac('sha256', b'Compton', b'Dr.Dre', 2)
        user.update_password(new_pwd)

        self.assertFalse(user.password_auth(pwd))
        self.assertTrue(user.password_auth(new_pwd))




if __name__ == '__main__':
    logging.basicConfig(level=settings.LOG_LVL_TEST)
    unittest.main()