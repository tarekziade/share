# demo
import requests
import os
from StringIO import StringIO

from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB, SALT
from fxakeys.crypto import generate_keypair, decrypt_data, get_kBr
from fxakeys.crypto import (encrypt_data, decrypt_data, public_encrypt,
                            public_decrypt)
from fxakeys.client.storage import UserStorage


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
            if 'encPrivKey' in data:
                encpriv = data['encPrivKey']
                priv = decrypt_data(encpriv, self.kbr)
            else:
                priv = None
            pub = data['pubKey']
        else:
            raise Exception(str(res.content))

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



if __name__ == '__main__':

    # both users are using the same email for
    # the sake of the demo here
    bill_email = tarek_email = "tarek@mozilla.com"
    app = "someapp"

    # tarek is a "some app" user.
    tarek = AppUser(email=tarek_email, app=app)

    # bill too (he uses the same account for the sake of the demo here)
    bill = AppUser(email=bill_email, app=app)

    # bill wants to send a message to tarek
    encrypted_data = bill.encrypt_data(tarek_email, "hey!")
    bill_storage = UserStorage(email=bill_email, app=app)
    url = bill_storage.share_content(tarek_email, encrypted_data, 'hey.txt')
    print url


    tarek_storage = UserStorage(email=tarek_email, app=app)
    encrypted_data = tarek_storage.get_shared_content(bill_email, 'hey.txt')

    # tarek gets the encrypted data and decrypts it
    msg = tarek.decrypt_data(bill_email, encrypted_data)
    assert msg == 'hey!'



