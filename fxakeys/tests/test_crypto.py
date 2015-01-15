from StringIO import StringIO
import os
import binascii
import unittest
import filecmp

from fxakeys.crypto import encrypt_data, decrypt_data, SymmetricBox
from fxakeys.crypto import generate_keypair, get_kBr
from fxakeys.crypto import public_encrypt, public_decrypt
from fxakeys.crypto import stream_encrypt, stream_decrypt
from fxakeys.crypto import encrypt_file, decrypt_file


_CAP = os.path.join(os.path.dirname(__file__), 'cap.png')


class TestCrypto(unittest.TestCase):

    def tearDown(self):
        if os.path.exists(_CAP + '.crypt'):
            os.remove(_CAP + '.crypt')

        if os.path.exists(_CAP + '.decrypt'):
            os.remove(_CAP + '.decrypt')

    def test_encryption(self):
        # basic symetric encryption
        secret = binascii.hexlify(os.urandom(32))
        message = 'secret'
        encrypted= encrypt_data(message, secret)
        self.assertEqual(decrypt_data(encrypted, secret), message)

    def test_symmetric_box(self):
        box = SymmetricBox(binascii.hexlify(os.urandom(32)))
        message = binascii.hexlify(os.urandom(1024))
        self.assertEqual(box.decrypt(box.encrypt(message)), message)

    def test_keypair(self):
        kB = os.urandom(32)
        client_id = 'whatever'
        kBr = get_kBr(kB, client_id)

        pub, priv, encrypted_priv = generate_keypair(kB, client_id)

        # let's verify the encrypted_key
        self.assertEqual(decrypt_data(encrypted_priv, kBr), priv)

    def test_pubencryption(self):
        kB = os.urandom(32)
        client_id = 'whatever'
        bob_pub, bob_priv, __ = generate_keypair(kB, client_id)

        kB2 = os.urandom(32)
        tarek_pub, tarek_priv, __ = generate_keypair(kB, client_id)

        message = 'yeah'
        enc = public_encrypt(message, tarek_pub, bob_priv)
        self.assertEqual(public_decrypt(enc, bob_pub, tarek_priv), message)

    def test_stream(self):
        kB = os.urandom(32)
        client_id = 'whatever'
        bob_pub, bob_priv, __ = generate_keypair(kB, client_id)

        kB2 = os.urandom(32)
        tarek_pub, tarek_priv, __ = generate_keypair(kB, client_id)

        message = '$' * 3000 + 'ok' + 'welp' * 100

        encrypted = list(stream_encrypt(StringIO(message), tarek_pub, bob_priv))
        enc_data = ''.join(encrypted)

        data = stream_decrypt(StringIO(enc_data), bob_pub, tarek_priv)
        data = ''.join(data)
        self.assertEqual(message, data)

    def test_file_encryption(self):
        kB = os.urandom(32)
        client_id = 'whatever'
        bob_pub, bob_priv, __ = generate_keypair(kB, client_id)

        kB2 = os.urandom(32)
        tarek_pub, tarek_priv, __ = generate_keypair(kB, client_id)

        encrypt_file(_CAP, _CAP + '.crypt', bob_pub, tarek_priv)
        decrypt_file(_CAP + '.crypt', _CAP + '.decrypt', tarek_pub, bob_priv)

        self.assertTrue(filecmp.cmp(_CAP, _CAP + '.decrypt'))
