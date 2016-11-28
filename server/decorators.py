"""
Useful decorators.
"""
import logging
from server.exceptions import NoUserRegisteredError

def user_required(f):
    """
    Checks if ther is at least one registered user in the database,
    if not, raises NoUserRegisteredError.
    """
    
    def wrap(self, *args, **kwargs):
        res = self._conn.execute('''SELECT * FROM user''')
        if (len(res.fetchall()) == 0):
            logging.debug('Tried to authenticate, but no users have been found '
                'in the database.')
            raise NoUserRegisteredError()
        return f(self, *args, **kwargs)
    
    wrap.__doc__ = f.__doc__
    wrap.__name__ = f.__name__
    return wrap
