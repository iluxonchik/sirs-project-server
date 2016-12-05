import logging
import base64
import server.settings as settings

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

        NOTE: the implementation is slightly dirty, since the router will
        actually look into the message content (because some messages require 
        tokens and others don't). There are cleaner solutions, but we're
        kind of out of time.
        """
        # TODO: decrypt, check token
        if settings.BASE64_MODE:
            logging.debug('NOTE: operating in base64 mode, actual received data'
                ' is: {}'.format(data))
            data = base64.b64decode(data)

        # last 3 bytes of received data

        logging.debug('Router received and decrypted data: {}'.format(data))
        
        return data

    def send(self, msg_type, data=b''):
        """
        Encrypt data, add MAC and send it to client.
        """
        # TODO: encrypt, add MAC
        logging.debug('Router send request msg_type: {}, data: {}'.format(
            msg_type, data))
        data_to_send = msg_type + data
        logging.debug('Router sending data to client: {}'.format(data_to_send))

        if settings.BASE64_MODE:
            data_to_send = base64.b64encode(data_to_send)
            logging.debug('NOTE: operating in base64 mode, '
                'actual data sent is:{}'.format(data_to_send))

        self._cli_sock.send(data_to_send)

