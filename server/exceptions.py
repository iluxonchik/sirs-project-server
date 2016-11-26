"""
Exception classes for the server module.
"""

class FileDoesNotExistError(ValueError):
    """
    The requested file does not exist.
    """
    pass