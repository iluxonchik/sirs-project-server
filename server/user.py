"""
User managment.
"""
import settings
from server.decorators import user_required

import sqlite3, os, logging
from server.exceptions import NoUserRegisteredError, UserAlreadyExistsError

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

    def _add_user_to_db(self, password):
        self._conn.execute('INSERT INTO user VALUES(?, ?)', 
            (self.username, password))
        self._conn.commit()

    def _set_user_password(self, password):
        self._conn.execute('UPDATE user SET password=? WHERE username=?',
                                                    (password, self.username))
        self._conn.commit()

    @user_required
    def password_auth(self, password):
        """
        Authenticates user based on user/password combination.

        Returns:
            True - login successful
            False - login unsuccessful
        """
        res = self._conn.execute(
            '''SELECT * FROM user where username=? and password=?''', 
                                                    (self._username, password))
        return len(res.fetchall()) > 0

    @user_required
    def token_auth(self, token):
        # TODO: check token validity
        pass

    def register(self, password):
        """
        Registers the current user in the database. If the user already exists,
        raises UserAlreadyExistsError.
        """
        res = self._conn.execute('SELECT * FROM user WHERE username=?',
                                                            (self.username,))
        if len(res.fetchall()) > 0:
            raise UserAlreadyExistsError("'{}' already exists in the database"
                .format(self.username))

        self._add_user_to_db(password)
        logging.info('User {} registered in the database.'
                                                        .format(self.username))

    @user_required
    def update_password(self, new_password):
        res = self._conn.execute('SELECT * FROM user WHERE username=?',
                                                            (self.username,))
        if len(res.fetchall()) != 1:
            raise NoUserRegisteredError("User with username '{}' is not "
                "registered in the system.".format(self.username))
        
        self._set_user_password(new_password)