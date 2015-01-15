import nacl
import nacl.utils
import nacl.secret
import binascii
import os

from nacl.public import PrivateKey, Box, PublicKey
import nacl.hash

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def _hkdf_expand(key, info):
    backend = default_backend()
    salt = '0' * len(key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info,
                backend=backend)
    return hkdf.derive(key)


def encrypt_data(data, secret):
    """
    data: the data to encrypt (bytes)
    secret: the encrytion key (hex)
    """
    secret = binascii.unhexlify(secret)
    box = nacl.secret.SecretBox(secret)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(data.encode(), nonce)
    return binascii.hexlify(encrypted)


def decrypt_data(data, secret):
    """
    data: the data to decrypt (hex)
    secret: the encrytion key (hex)
    """
    secret = binascii.unhexlify(secret)
    data = binascii.unhexlify(data)
    box = nacl.secret.SecretBox(secret)
    encrypted_data = nacl.utils.EncryptedMessage(data)
    return box.decrypt(encrypted_data)


class SymmetricBox(object):
    def __init__(self, secret):
        assert len(secret) == 64, 'The secret must be an hex of 64'
        self.secret = secret

    def encrypt(self, message):
        """Encrypts a bytes message.
        """
        return encrypt_data(message, self.secret)

    def decrypt(self, message):
        """Decrypts an hex message
        """
        return decrypt_data(message, self.secret)


def get_kBr(kB, client_id):
    """Given a kB and a client_id returned from the FxA auth server,
    returns a kBr
    """
    kBr = _hkdf_expand(kB, client_id)
    return binascii.hexlify(kBr)


def generate_keypair(kB, client_id):
    """Given a kbR and a client_id returned from the FxA auth server
    returns a key pair (public+encrypted private key)
    """
    kBr = get_kBr(kB, client_id)
    priv = PrivateKey.generate()
    pub = priv.public_key
    pub = binascii.hexlify(pub.encode())
    # encrypt the priv key with kBr
    priv = binascii.hexlify(priv.encode())
    encrypted_priv = encrypt_data(priv, kBr)
    #priv = binascii.hexlify(priv.encode())
    return pub, priv, encrypted_priv


def public_encrypt(message, target_pub, origin_priv):
    priv = PrivateKey(binascii.unhexlify(origin_priv))
    pub = PublicKey(binascii.unhexlify(target_pub))
    box = Box(priv, pub)
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    return box.encrypt(message, nonce)


def public_decrypt(message, origin_pub, target_priv):
    priv = PrivateKey(binascii.unhexlify(target_priv))
    pub = PublicKey(binascii.unhexlify(origin_pub))
    box = Box(priv, pub)
    return box.decrypt(message)


_CHUNK = 4096

# XXX is this the formula?
_ENC_CHUNK = _CHUNK + Box.NONCE_SIZE + 16
_HEX_ENC_CHUNK = _ENC_CHUNK * 2

def stream_encrypt(stream, target_pub, origin_priv):
    """
    encrypting file process:

    1/ build a box with a random nonce
    2/ for each 4096 bytes
        build a hash
        encrypt
        send them to the iterator

    3/ at the end create a special control message
       that is the list of chunk hashes.
       encrypt it and send it to the iterator
       this special control message can be used to
       make sure the encrypted file was not tampered.
    """
    priv = PrivateKey(binascii.unhexlify(origin_priv))
    pub = PublicKey(binascii.unhexlify(target_pub))
    box = Box(priv, pub)
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    hashes = []

    while True:
        data = stream.read(_CHUNK)
        if not data:
            break
        hashes.append(nacl.hash.sha256(data))
        enc = box.encrypt(data, nonce)
        yield binascii.hexlify(enc)

    control = ':::'.join(hashes)
    yield binascii.hexlify(box.encrypt(control, nonce))


def stream_decrypt(stream, hash, origin_pub, target_priv):
    """To decrypt the file

    stream is hex !!

    1/ build a box
    2/ for each 4096 bytes
         decrypt
         build the hash
         send the decrypted data to the iterator
    3/ control the hashes send 'OK' or 'KO' to the iterator
    """
    priv = PrivateKey(binascii.unhexlify(target_priv))
    pub = PublicKey(binascii.unhexlify(origin_pub))
    box = Box(priv, pub)

    hash = binascii.unhexlify(hash)
    hashes = box.decrypt(hash).split(':::')
    pos = 0

    while True:
        data = stream.read(_HEX_ENC_CHUNK)
        if not data:
            break

        data = box.decrypt(binascii.unhexlify(data))
        assert nacl.hash.sha256(data) == hashes[pos]
        yield data
        pos += 1
