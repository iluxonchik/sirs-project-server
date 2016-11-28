"""
User managment.
"""
import server.settings as settings

import sqlite3, os, logging
from server.exceptions import NoUserRegisteredError

class User(object):
    
    def __init__(self, username):
        self._username = username
        self._conn = self._get_db_conn()

    @property
    def username(self):
        return self._username

    def _get_db_conn(self):
        if os.path.exists(settings.DB_NAME):
            logging.info('Database {} already exists'.format(settings.DB_NAME))
            conn = sqlite3.connect(settings.DB_NAME)
        else:
            logging.info('Database {} does not exist. '
                            'Creating new database...'.format(settings.DB_NAME))
            conn = sqlite3.connect(settings.DB_NAME)
            conn.execute('''CREATE TABLE user 
                                        (username string, password string)''')
        
        return conn

    def _check_user_exists(self):
        res = self._conn.execute('''SELECT * FROM user''')
        if (len(res.fetchall()) == 0):
            logging.debug('Tried to authenticate, but no users have been found '
                'in the database.')
            raise NoUserRegisteredError()

    def password_auth(self, password):
        """
        Authenticates user based on user/password combination.

        Returns:
            True - login successful
            False - login unsuccessful
        """
        self._check_user_exists()
        res = self._conn.execute(
            '''SELECT * FROM user where username=? and password=?''', 
                                                    (self._username, password))
        return len(res.fetchall()) > 0

    def token_auth(self, token):
        # TODO: check token validity
        self._check_user_exists()
        pass