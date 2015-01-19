import requests

from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB
from fxakeys.crypto import generate_keypair, get_kBr
from fxakeys.crypto import (public_encrypt, decrypt_data,
                            public_decrypt, stream_encrypt, stream_decrypt)


class AppUser(object):
    def __init__(self, email, app,
                 keyserver='http://localhost:8000',
                 client_id=CLIENT_ID, kb=KB):
        self.server = keyserver
        self.email = email
        self.app = app
        self.token = get_oauth_token()
        self.session = requests.Session()
        self.session.headers['Authorization'] = 'Bearer %s' % self.token
        self.client_id = client_id
        self.kb = kb
        self.kbr = get_kBr(kb, client_id)
        self._key_cache = {}
        self.pub, self.priv = self.get_key(self.email)

    def get_key(self, email):
        if email in self._key_cache:
            return self._key_cache[email]

        res = self.session.get(self.server + '/%s/apps/%s/key' % (email,
                                                                  self.app))
        if res.status_code == 404:
            # no key, we need to generate it and publish it
            pub, priv, encpriv = generate_keypair(self.kb, self.client_id)
            data = {'pubKey': pub, 'encPrivKey': encpriv}
            self.session.post(self.server + '/%s/apps/%s/key' % (email,
                                                                 self.app),
                              data=data)
        elif res.status_code == 200:
            data = res.json()
            if 'encPrivKey' in data:
                encpriv = data['encPrivKey']
                priv = decrypt_data(encpriv, self.kbr)
            else:
                priv = None
            pub = data['pubKey']
        else:
            raise Exception(str(res.content))

        self._key_cache[email] = pub, priv
        return pub, priv

    def encrypt_data(self, target, data):
        # 1. get the target public key.
        pub, __ = self.get_key(target)

        # 2. encrypt the data using the target key
        return public_encrypt(data, pub, self.priv)

    def decrypt_data(self, origin, data):
        # 1. get the sender public key.
        pub, __ = self.get_key(origin)
        return public_decrypt(data, pub, self.priv)

    def stream_encrypt(self, stream, target):
        # 1. get the target public key.
        pub, __ = self.get_key(target)
        return stream_encrypt(stream, pub, self.priv)

    def stream_decrypt(self, stream, origin):
        # 1. get the sender public key.
        pub, __ = self.get_key(origin)
        return stream_decrypt(stream, pub, self.priv)
