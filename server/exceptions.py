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