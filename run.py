"""
Startup script.
"""
import logging, base64, os
from server.settings import LOG_LVL
from server.server import Server

from server.bluetooth.event_bus import BluetoothEventBus
from server.bluetooth.protocol import Protocol
from server.listeners import DirectoryEncryptorListener, DirectoryDecryptorListener


def _bt_server_test():
    s = Server()
    s.start()

def _event_bus_test():
    key = key = base64.b64encode(os.urandom(32))
    eb = BluetoothEventBus(Protocol)
    de = DirectoryEncryptorListener(key)
    dd = DirectoryDecryptorListener(key)

    eb.subscribe(de, msg_type=(Protocol.ENCRYPT, ))
    eb.subscribe(dd, msg_type=(Protocol.DECRYPT, ))

if __name__ == '__main__':
    logging.basicConfig(level=LOG_LVL)
    _bt_server_test()
    
    import pdb; pdb.set_trace()
