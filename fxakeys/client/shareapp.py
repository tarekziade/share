# demo
import requests
import os
from StringIO import StringIO
import argparse


from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB
from fxakeys.crypto import generate_keypair, decrypt_data, get_kBr
from fxakeys.crypto import (encrypt_data, decrypt_data, public_encrypt,
                            public_decrypt)
from fxakeys.client.storage import UserStorage


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
        self.pub, self.priv = self.get_key(self.email)

    def get_key(self, email):
        print('Making sure %r keypair is published in the Key service' % email)
        res = self.session.get(self.server + '/%s/apps/%s/key' % (email, self.app))
        if res.status_code == 404:
            # no key, we need to generate it and publish it
            pub, priv, encpriv = generate_keypair(self.kb, self.client_id)
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


def share():
    parser = argparse.ArgumentParser(description='Share a file with someone.')
    parser.add_argument('file', type=str, help='File to share')
    parser.add_argument('target', type=str, help='Target e-mail')
    parser.add_argument('--email', type=str, help='Your e-mail',
                        default='tarek@mozilla.com')

    args = parser.parse_args()

    filename = os.path.basename(args.file)
    user = AppUser(email=args.email, app="share")

    print('Encrypting file..')
    with open(args.file) as f:
        encrypted_data = user.encrypt_data(args.target, f.read())

    print('Pushing file in the storage service')
    storage = UserStorage(email=args.email, app="share")
    storage.share_content(args.target, encrypted_data, filename)
    print('Shared!')


def get():
    parser = argparse.ArgumentParser(description='Get a file shared by someone.')
    parser.add_argument('sender', type=str, help='Sender e-mail')
    parser.add_argument('--email', type=str, help='Your e-mail',
                        default='tarek@mozilla.com')

    args = parser.parse_args()

    user = AppUser(email=args.email, app="share")

    # get_shared_content() actually point to the other user storage
    #
    storage = UserStorage(email=args.email, app="share")
    print('Get the encrypted file from the storage..')
    files = storage.get_shared_list(args.sender)
    filename = files[0]
    encrypted_data = storage.get_shared_content(args.sender, filename)

    print('Decrypt the file...')
    data = user.decrypt_data(args.sender, encrypted_data)

    if os.path.exists(filename):
        raise IOError('File already exist')

    with open(filename, 'w') as f:
        f.write(data)

    print(filename)


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

    print bill_storage.list()
    print bill_storage.list(app)

    tarek_storage = UserStorage(email=tarek_email, app=app)
    encrypted_data = tarek_storage.get_shared_content(bill_email, 'hey.txt')

    # tarek gets the encrypted data and decrypts it
    msg = tarek.decrypt_data(bill_email, encrypted_data)
    assert msg == 'hey!'



