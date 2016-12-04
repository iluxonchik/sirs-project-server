import logging
import server.settings as settings

from bluetooth import *

class Server(object):
    def __init__(self):
        pass

    def start(self):
        logging.info('Startig bluetooth server...')

        server_sock, port = self._start_bluetooth_service()

        while True:
            cli_sock, cli_info = self._wait_for_client_connection(server_sock)
            self._treat_client_conneciton(cli_sock, cli_info)

        logging.info('Terminating bluetooth listener...')
        server_sock.close()

    def _start_bluetooth_service(self):
        server_sock = BluetoothSocket(RFCOMM)
        server_sock.bind(("", PORT_ANY))
        server_sock.listen(1)

        port = server_sock.getsockname()[1]


        advertise_service(server_sock, settings.BT_SERVICE_NAME,
                          service_id=settings.BT_SERVICE_UUID,
                          service_classes=[
                              settings.BT_SERVICE_UUID, 
                              SERIAL_PORT_CLASS],
                          profiles=[SERIAL_PORT_PROFILE],
                          )
        logging.info(
            'Waiting for connection on RFCOMM channel {}'.format(port))

        return (server_sock, port)

    def _wait_for_client_connection(self, server_sock):
        logging.info('Waiting for connection from client...')
        cli_sock, cli_info = server_sock.accept()
        logging.info('Accepted bluetooth connection from {}'.format(cli_info))

        return (cli_sock, cli_info)

    def _treat_client_conneciton(self, cli_sock, cli_info):
        # TODO: 
        #       1. Negotiate a symmetic session key (Diffie-Hellman) (includes 
        #          authenticating values)
        #       2. Instantiate BluetoothEventBus + listeners
        #       3. Send/receive BT msgs (always encrypted with session key)

        session_key = self._generate_session_key()  # negortiate sesison key
        eb = self._init_event_bus(cli_sock)
        try:
            while True:
                data = cli_sock.recv(1024)
                if len(data) == 0: break
                # TODO: decrypt data
                logging.info("Received: {}".format(data))
                # cli_sock.send(b'Hello, world!')
        except IOError as e:
            logging.warn('IOError: {}'.format(str(e)))

        logging.info('Disconnected from {}'.format(cli_info))
        
        cli_sock.close()
        # TODO: send 'Encrypt!' message to event bus

    def _generate_session_key(self):
        """
        Genreate session key (Diffie-Hellman).
        
        Messages sent and received here are not encrypted. Values 'a' and 'b'
        are authenticated.

        Returs:
            session_key
        """
        logging.info('Initiating session key genreation...')
        pass

    def _init_event_bus(self, cli_sock):
        """
        Init event bus and listeners.

        Returns:
            event_bus (BluetoothEventBus)
        """
        logging.info('Initializing event bus...')
        pass
