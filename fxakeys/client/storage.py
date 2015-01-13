# demo
import requests
import os
from StringIO import StringIO

from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB, SALT
from fxakeys.crypto import generate_keypair, decrypt_data, get_kBr
from fxakeys.crypto import (encrypt_data, decrypt_data, public_encrypt,
                            public_decrypt)



def url_join(*parts):
    # XXX ugly shortcut
    def clean(part):
        return part.strip('/')

    return '/'.join([clean(part) for part in parts])


# XXX TODO: obfuscate directory and file names
#
class UserStorage(object):

    def __init__(self, email, app,
                  keyserver='http://localhost:9000'):
        self.server = keyserver
        self.email = email
        self.app = app
        self.token = get_oauth_token()
        self.session = requests.Session()
        self.session.headers['Authorization'] = 'Bearer %s' % self.token

    def share_content(self, target, content, filename, metadata=None):
        folder_id = url_join('/' + self.app, 'sharing', target)
        return self.upload(StringIO(content), folder_id, filename, metadata)

    def get_shared_content(self, origin, name):
        filepath = url_join(self.app, 'sharing', origin, name)
        return self.download(filepath)

    def list(self, path='/'):
        if path == '/':
            path = url_join(self.server, self.email, 'content')
        else:
            path = url_join(self.server, self.email, 'content', path)

        res = self.session.get(path)
        return res.json()

    def upload(self, file_, folder_id, filename, metadata=None):
        data = {'folder_id': folder_id}
        if metadata is not None:
            data.update(metadata)
        files = {filename: file_}
        path = url_join(self.server, self.email, 'upload')

        res = self.session.post(path, data=data, files=files)
        return url_join(self.server, self.email, 'content',
                        res.json()['path'])

    def download(self, filepath):
        path = url_join(self.server, self.email, 'content', filepath)
        res = self.session.get(path)
        return res.content
