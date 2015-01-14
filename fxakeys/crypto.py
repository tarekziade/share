import nacl
import nacl.utils
import nacl.secret
import binascii
from nacl.public import PrivateKey, Box, PublicKey
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def _hkdf_expand(key, info):
    backend = default_backend()
    salt = '0' * len(key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info,
                backend=backend)
    return hkdf.derive(key)


def encrypt_data(key, secret):
    """
    Key: the data to encrypt
    Secret: the encrytion key (hex)
    """
    secret = binascii.unhexlify(secret)

    box = nacl.secret.SecretBox(secret)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(key.encode(), nonce)
    return binascii.hexlify(encrypted), nonce


def decrypt_data(key, secret):
    """
    Key: the data to decrypt (hex)
    Secret: the encrytion key (hex)
    """
    secret = binascii.unhexlify(secret)
    key = binascii.unhexlify(key)

    box = nacl.secret.SecretBox(secret)
    encrypted_private_key = nacl.utils.EncryptedMessage(key)
    private_key = box.decrypt(encrypted_private_key)
    return private_key


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
    encrypted_priv, nonce = encrypt_data(priv, kBr)
    priv = binascii.hexlify(priv.encode())
    return pub, priv, encrypted_priv, binascii.hexlify(nonce)


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



if __name__ == '__main__':

    # given a kB and a client_id we can generate a key pair
    client_id = '021fd64aa9661fa1'

    kB = os.urandom(32)
    kBr = get_kBr(kB, client_id)
    key = binascii.hexlify(os.urandom(32))

    assert kBr == get_kBr(kB, client_id)


    enc, nonce = encrypt_data(key, kBr)
    assert decrypt_data(enc, kBr) == key


    pub, priv, encrypted_priv, nonce = generate_keypair(kB, client_id)
    decrypt_data(encrypted_priv, kBr)
