# demo
import requests

from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB, SALT
from fxakeys.crypto import generate_keypair, decrypt_key, get_kBr


class AppUser(object):
    def __init__(self, email, app,
                 keyserver='http://localhost:8000',
                 client_id=CLIENT_ID, kb=KB, salt=SALT):
        self.server = keyserver
        self.email = email
        self.app = app
        self.salt = salt
        self.token = get_oauth_token()
        self.session = requests.Session()
        self.session.headers['Authorization'] = 'Bearer %s' % self.token
        self.client_id = client_id
        self.kb = kb
        self.kbr = get_kBr(kb, client_id, salt)
        self.pub, self.priv = self.get_key(self.email)

    def get_key(self, email):
        res = self.session.get(self.server + '/%s/apps/%s/key' % (email, self.app))
        if res.status_code == 404:
            # no key, we need to generate it and publish it
            pub, priv, encpriv, nonce = generate_keypair(self.kb,
                    self.client_id, self.salt)
            data = {'pubKey': pub, 'encPrivKey': encpriv}
            self.session.post(self.server + '/%s/apps/%s/key' % (email, self.app),
                              data=data)
        elif res.status_code == 200:
            data = res.json()
            encpriv = data['encPrivKey']
            self.priv = decrypt_key(encpriv, self.kbr)
            self.pub = data['pubKey']
        else:
            raise Exception(str(res.content))

        return self.pub, self.priv

    def encrypt_data(target, data):
        # 1. get the target public key.

        # 2. encrypt the data using the target key.

        # 3. print the data to be copy-pasted
        pass

    def decrypt_data(data):
        # 1. get back our keys

        # 2. decrypt the private key using kB

        # 3. print the decrypted message
        pass



if __name__ == '__main__':

    tarek = AppUser(email="tarek@mozilla.com", app="someapp")

