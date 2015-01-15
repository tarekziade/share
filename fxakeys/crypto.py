import nacl
import nacl.utils
import nacl.secret
import binascii
import os
import hashlib

from nacl.public import PrivateKey, Box, PublicKey

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class EncryptError(Exception):
    pass


class DecryptError(Exception):
    pass


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
        if len(secret) != 64:
            raise TypeError('The secret must be an hex of 64')

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
_ENC_HASH_SIZE = 144


def stream_encrypt(stream, target_pub, origin_priv):
    priv = PrivateKey(binascii.unhexlify(origin_priv))
    pub = PublicKey(binascii.unhexlify(target_pub))
    box = Box(priv, pub)

    # we should vary the nonce. see
    # http://crypto.stackexchange.com/questions/22435/public-key-encryption-and-big-files-with-nacl
    #
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    hash = hashlib.sha256()

    while True:
        data = stream.read(_CHUNK)
        if not data:
            break

        # XXX this is growing in memory. maybe hash
        # should be built with hash - 1 + data instead
        # of the whole data
        hash.update(data)
        encrypted_hash = box.encrypt(hash.digest(), nonce)
        enc = box.encrypt(data, nonce)
        yield binascii.hexlify(enc) + binascii.hexlify(encrypted_hash)


def stream_decrypt(stream, origin_pub, target_priv):
    priv = PrivateKey(binascii.unhexlify(target_priv))
    pub = PublicKey(binascii.unhexlify(origin_pub))
    box = Box(priv, pub)

    hash = hashlib.sha256()

    while True:
        data = stream.read(_HEX_ENC_CHUNK + _ENC_HASH_SIZE)
        if not data:
            break

        found_hash = data[-_ENC_HASH_SIZE:]
        found_hash = box.decrypt(binascii.unhexlify(found_hash))
        data = data[:-_ENC_HASH_SIZE]
        data = box.decrypt(binascii.unhexlify(data))
        hash.update(data)
        if hash.digest() != found_hash:
            raise DecryptError('Hash mismatch')

        yield data


# XXX add a header at the beginning of the file
# that gives the hash kind
def encrypt_file(source, target, target_pub, origin_priv):
    s = open(source)
    try:
        enkriptor = stream_encrypt(s, target_pub, origin_priv)
        with open(target, 'w') as f:
            for chunk in enkriptor:
                f.write(chunk)
    finally:
        s.close()


def decrypt_file(source, target, origin_pub, target_priv):
    s = open(source)

    try:
        dekriptor = stream_decrypt(s, origin_pub, target_priv)

        with open(target, 'w') as f:
            for chunk in dekriptor:
                f.write(chunk)
    finally:
        s.close()
