from hashlib import sha256
import base64
from server.utils import encrypt_data, compute_mac

def _get_default_key():
    key = b'Diffie-Hellman negotiated key'

    h = sha256()
    h.update(key)
    key = h.digest()
    return key

def get_from_file(filename):
    f = open(filename, 'rb')
    cont = f.read()
    cont = base64.b64decode(cont)
    return cont

def gen_msg(data, key=None, iv=None, mac=None, b64=True):
    if key is None:
        key = _get_default_key()
    if iv is None:
        iv = b'1'.rjust(16, b'0')
    if mac is None:
        mac = compute_mac(key, data, iv)

    enc_data = encrypt_data(data, key, iv)

    msg = enc_data + iv + mac

    if b64:
        msg = base64.b64encode(msg)

    return msg

def gen_msg_to_file(filename, data, key=None, iv=None, mac=None, b64=True):
    content = gen_msg(data, key, iv, mac, b64)
    f = open(filename, 'wb')
    f.write(content)
