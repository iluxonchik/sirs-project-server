import logging, os, base64
from hashlib import sha256

import server.settings as settings
from server.bluetooth.protocol import Protocol
from server.bluetooth.event_bus import BluetoothEventBus
from server.listeners import (DirectoryEncryptorListener, 
    DirectoryDecryptorListener, UserPasswordAuthListener, 
    InternalDirectoryEncryptorListner)

from server.bluetooth.blue_router import BlueRouter

from bluetooth import*

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
        (eb, router) = self._init_event_bus(cli_sock, session_key)
        try:
            while True:
                data = cli_sock.recv(1024)
                data = router.receive(data)  # decrypt and check token

                if data is None:
                    # if something went wrong, for example, invalid MAC or IV
                    continue

                if len(data) == 0: break
                
                logging.info("Received: {}".format(data))
                eb.process(data)
                
                # cli_sock.send(b'Hello, world!')
        except IOError as e:
            logging.warn('IOError: {}'.format(str(e)))

        logging.info('Disconnected from {}'.format(cli_info))
        
        cli_sock.close()
        eb.process(Protocol.ENCRYPT_INTERNAL)

    def _generate_session_key(self):
        """
        Genreate session key (Diffie-Hellman).
        
        Messages sent and received here are not encrypted. Values 'a' and 'b'
        are authenticated.

        {msg}

        Returs:
            session_key: 256-bit key (to be used with AES)
        """
        logging.info('Initiating session key generation...')
        
        # TODO: negotiate key
        negotiated_key = b'Diffie-Hellman negotiated key'
        
        h = sha256()
        h.update(negotiated_key)
        session_key = h.digest()
        return session_key

    def _init_listeners(self, cli_sock, event_bus, router):
        """
        Init listeners.
        """
        h = sha256()
        h.update(b'hello')
        sesion_key = h.digest()
        key = base64.b64encode(sesion_key)

        ie = InternalDirectoryEncryptorListner()
        de = DirectoryEncryptorListener(cli_sock=cli_sock, router=router, 
            internal_enc=ie)
        dd = DirectoryDecryptorListener(cli_sock=cli_sock, router=router, 
            internal_enc=ie)

        ua = UserPasswordAuthListener(router, internal_enc=ie)

        event_bus.subscribe(de, msg_type=(Protocol.ENCRYPT,))
        event_bus.subscribe(dd, msg_type=(Protocol.DECRYPT,))
        event_bus.subscribe(ua, msg_type=(Protocol.PWD_LOGIN,))
        event_bus.subscribe(ie, msg_type=(Protocol.ENCRYPT_INTERNAL,))

    def _init_event_bus(self, cli_sock, sesion_key):
        """
        Init event bus and listeners.

        Returns:
            (event_bus, blue_router)
        """
        logging.info('Initializing event bus...')
        event_bus = BluetoothEventBus(protocol=Protocol)
        blue_router = BlueRouter(cli_sock, event_bus, sesion_key)
        self._init_listeners(cli_sock, event_bus, blue_router)
        return (event_bus, blue_router)


