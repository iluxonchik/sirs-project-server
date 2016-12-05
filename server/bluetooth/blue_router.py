import logging

class BlueRouter(object):
    """
    Receives messages via bluetooth, decrypts them, checks the token.
    If token is invalid, notifies event bus.
    
    Sends messages via bluetooth to the client, encrypting them before doing
    so.
    """
    def __init__(self, cli_sock, eb, session_key):
        self._eb = eb
        self._key = session_key
        self._cli_sock = cli_sock

    def receive(self, data):
        """
        Decrypt bluetooth message, check MAC and check the token. 
        If the token is invalid, notify event bus.
        """
        # TODO:
        logging.debug('Router received and decrypted data: {}'.format(data))
        return data

    def send(self, data):
        """
        Encrypt data, add MAC and send it to client.
        """
        logging.debug('Router sending data to client: {}'.format(data))
