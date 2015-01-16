# demo
import requests
import os
from StringIO import StringIO

from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB
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

    def share_content(self, target, stream, filename, metadata=None):
        folder_id = url_join('/' + self.app, 'sharing', target)
        return self.upload(stream, folder_id, filename, metadata)

    def get_shared_content(self, origin, name):
        # getting content from the origin user /content/app/sharing/email
        filepath = url_join(self.app, 'sharing', self.email, name)
        return self.download(filepath, email=self.email)

    def get_shared_list(self, origin):
        path = url_join(self.app, 'sharing', self.email)
        return [item['name'] for item in self.list(path, email=origin)['items']
                if item['type'] == 'file']

    def list(self, path='/', email=None):
        if email is None:
            email = self.email

        if path == '/':
            path = url_join(self.server, email, 'content')
        else:
            path = url_join(self.server, email, 'content', path)

        res = self.session.get(path)
        return res.json()

    def upload(self, stream, folder_id, filename, metadata=None):
        path = url_join(self.server, self.email, 'upload')

        headers = {'Content-Disposition': 'attachment',
                   'Content-Transfer-Encoding': 'binary',
                   'filename': filename,
                   'folder_id': folder_id}

        if metadata is not None:
            headers.update(metadata)

        size = stream.len
        pos = 0

        for data in stream:
            clen = len(data)
            headers['Content-Range'] = 'bytes %s-%s/%s' % (pos, clen - 1,
                                                           size)
            headers['Content-Length'] = clen
            res = self.session.post(path, data=data, headers=headers)
            pos += len(data)

        return url_join(self.server, self.email, 'content',
                        res.json()['path'])

    def download(self, filepath, email=None):
        if email is None:
            email = self.email
        path = url_join(self.server, email, 'content', filepath)
        res = self.session.get(path)
        return res.content
