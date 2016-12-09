import logging, os, base64, sys
from hashlib import sha256

import server.settings as settings
from server.bluetooth.protocol import Protocol
from server.bluetooth.event_bus import BluetoothEventBus
from server.listeners import (DirectoryEncryptorListener, 
    DirectoryDecryptorListener, UserPasswordAuthListener, 
    InternalDirectoryEncryptorListner)

from server.bluetooth.blue_router import BlueRouter
from diffiehellman.diffiehellman import DiffieHellman

from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 

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

        session_key = self._generate_session_key(cli_sock)  # negortiate sesison key
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

    def _generate_session_key(self, cli_sock):
        """
        Genreate session key (Diffie-Hellman).
        
        Messages sent and received here are not encrypted. Values 'a' and 'b'
        are authenticated.

        {msg}

        Returs:
            session_key: 256-bit key (to be used with AES)
        """
        logging.info('Initiating session key generation...')
        
        if settings.SAFE_MODE:
            negotiated_key = b'Diffie-Hellman negotiated key'
            
            h = sha256()
            h.update(negotiated_key)
            session_key = h.digest()
            return session_key 

        if settings.CHECK_CERTIFICATES:
            return os.system('openssl verify -verbose -CAfile {} '
                'Intermediate.pem'.format(settings.ROOT_CERT_PATH, 
                                            settings.CLIENT_CERT_PATH)) == 0 

        if settings.MOCK_SESSION_KEY:
            negotiated_key = b'Diffie-Hellman negotiated key'
            
            h = sha256()
            h.update(negotiated_key)
            session_key = h.digest()
            return session_key
        else:
            # Don't mock
            dh = DiffieHellman()
            dh.generate_public_key()
            public_key = dh.public_key

            if settings.SIGN_DH_PUBLIC:
                # value||siganture of value
                public_key = public_key + self._rsa_sign(public_key)

            if settings.BASE64_MODE:
                public_key = base64.b64encode(public_key)

            cli_sock.send(public_key)

            client_public = cli_sock.receive(1024)

            if settings.BASE64_MODE:
                client_public = base64.b64decode(client_public)
            
            if settings.SIGN_DH_PUBLIC:
                # value||siganture of value
                signature = client_public[len(client_public - 32):]
                data = client_public[:len(client_public) - 32]
                if not self._rsa_check_signature(data, signature):
                    logging.error('Invalid signature in Diffie-Hellman')
                    sys.exit()
            # NOTE: dh.generate_shared_secret() returns sha-256 digest of the
            # obtained shared key
            return dh.generate_shared_secret(client_public, echo_return_key=True)


    def _rsa_sign(self, public_key):
        key = open(settings.PRIV_KEY_PATH, "r").read() 
        rsakey = RSA.importKey(key) 
        signer = PKCS1_v1_5.new(rsakey) 
        digest = SHA256.new() 
        # It's being assumed the data is base64 encoded, 
        # so it's decoded before updating the digest 
        digest.update(base64.b64decode(public_key)) 
        sign = signer.sign(digest) 
        return sign

    def _rsa_check_signature(self, data, signature):
        pub_key = open(settings.PUB_KEY_PATH, "r").read() 
        rsakey = RSA.importKey(pub_key) 
        signer = PKCS1_v1_5.new(rsakey) 
        digest = SHA256.new() 
        # Assumes the data is base64 encoded to begin with
        digest.update(data)
        if signer.verify(digest, signature):
            return True
        return False

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


