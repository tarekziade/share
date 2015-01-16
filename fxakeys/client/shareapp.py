# demo
import requests
import os
from StringIO import StringIO
import argparse


from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB
from fxakeys.crypto import generate_keypair, decrypt_data, get_kBr
from fxakeys.crypto import (encrypt_data, decrypt_data, public_encrypt,
                            public_decrypt, stream_encrypt, stream_decrypt,
                            enc_size)
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
        self._key_cache = {}
        self.pub, self.priv = self.get_key(self.email)

    def get_key(self, email):
        if email in self._key_cache:
            return self._key_cache[email]

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


def share():
    parser = argparse.ArgumentParser(description='Share a file with someone.')
    parser.add_argument('file', type=str, help='File to share')
    parser.add_argument('target', type=str, help='Target e-mail')
    parser.add_argument('--email', type=str, help='Your e-mail',
                        default='tarek@mozilla.com')

    args = parser.parse_args()

    filename = os.path.basename(args.file)
    user = AppUser(email=args.email, app="share")
    storage = UserStorage(email=args.email, app="share")

    print('Encrypting and sending file by chunks...')

    class Chunker(object):
        len = enc_size(os.path.getsize(args.file))
        stream = user.stream_encrypt(open(args.file), args.target)

        def __iter__(self):
            return self

        def next(self):
            return self.stream.next()

    storage.share_content(args.target, Chunker(), filename)

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

    # XXX should get by chunk
    from fxakeys.crypto import _HEX_ENC_CHUNK

    if os.path.exists(filename):
        raise IOError('File already exist')


    class Reader(object):
        end = _HEX_ENC_CHUNK - 1
        start = 0

        def read(self, size=_HEX_ENC_CHUNK):

            range = self.start, self.end
            try:
                return storage.get_shared_content(args.sender, filename, range)
            finally:
                self.start = self.end + 1
                self.end = self.start + size - 1


    with open(filename, 'w') as f:
        for chunk in user.stream_decrypt(Reader(), args.sender):
            f.write(chunk)

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



