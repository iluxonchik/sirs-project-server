"""
Exception classes for the server module.
"""

class FileDoesNotExistError(ValueError):
    """
    The requested file does not exist.
    """
    pass

class NoUserRegisteredError(ValueError):
    """
    No registered user in the system has been found.
    """
    pass

class UserAlreadyExistsError(ValueError):
    """
    Tried to register a user when there is already an entry with such username
    in the system.
    """
    pass

class SymKeyNotFoundError(ValueError):
    """
    Tried to register a user when there is already an entry with such username
    in the system.
    """
    pass