import logging
import base64
import server.settings as settings
from server.utils import encrypt_data, decrypt_data, check_mac, compute_mac

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
        self._counter = 0  # used for IV's and to gurantee freshness

    def receive(self, data):
        """
        Decrypt bluetooth message, check MAC and check the token. 
        If the token is invalid, notify event bus.

        Received message structure: {msg}Ks, IV, MAC(msg||IV)
        """
        # TODO: decrypt, check token
        if settings.BASE64_MODE:
            logging.debug('NOTE: operating in base64 mode, actual received data'
                ' is: {}'.format(data))
            data = base64.b64decode(data)

        # MAC is last 32 bytes of data
        data_len = len(data)
        mac = data[data_len-32:]
        data = data[:data_len-32]
        data_len = data_len-32
        logging.debug('\tReceived message MAC is {}'.format(mac))


        # IV is last 16 bytes
        iv = data[data_len-16:]
        data = data[:data_len-16]
        data_len = data_len-16
        logging.debug('\tReceived mesasge IV is {}'.format(iv))

        if not self._is_valid_iv(iv):
            logging.warn('INVALID IV in received mesasge, returning...')
            return
        else:
            logging.debug('Valid IV')

        # Decrypt the message
        data = decrypt_data(data, self._key, iv)

        if not check_mac(data, iv, mac):
            logging.warn('INVALID MAC in received message, returning...')
            return

        logging.debug('Router received and decrypted data: {}'.format(data))
        
        return data

    def send(self, msg_type, data=b''):
        """
        Encrypt data, add MAC and send it to client.
        """
        logging.debug('Router send request msg_type: {}, data: {}'.format(
            msg_type, data))
        data_to_send = msg_type + data
        logging.debug('Router sending data to client: {}'.format(data_to_send))

        iv = self._get_iv()

        data = encrypt_data(data_to_send, self._key, iv)

        mac = compute_mac(self._key, data, iv)

        data_to_send = data + mac

        if settings.BASE64_MODE:
            data_to_send = base64.b64encode(data_to_send)
            logging.debug('NOTE: operating in base64 mode, '
                'actual data sent is:{}'.format(data_to_send))

        self._cli_sock.send(data_to_send)

    def _get_iv(self):
        self._counter = self._counter + 1
        iv = str(self._counter).encode()
        iv = iv.rjust(16, b'0')
        return iv

    def _is_valid_iv(self, iv):
        iv = int(iv)
        logging.debug('\tReceived IV: {}, current coutner value: {}'.format(
            iv, self._counter))
        return iv > self._counter
