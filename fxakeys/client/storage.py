# demo
import requests
import os
from StringIO import StringIO

from fxakeys.fxaoauth import get_oauth_token, CLIENT_ID, KB, SALT
from fxakeys.crypto import generate_keypair, decrypt_data, get_kBr
from fxakeys.crypto import (encrypt_data, decrypt_data, public_encrypt,
                            public_decrypt)



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
        folder_id = os.path.join('/' + self.app, 'sharing', target)
        return self.upload(StringIO(content), folder_id, filename, metadata)

    def get_shared_content(self, origin, name):
        path = self.email + '/content/' + self.app + '/sharing/' + origin
        res = self.session.get(self.server + '/' + path + '/' + name)
        return res.content

    def list(self, path'/'):
        pass

    def upload(self, file_, folder_id, filename, metadata=None):
        data = {'folder_id': folder_id}
        data.update(metadata)
        files = {filename: file_}
        res = self.session.post(self.server + '/%s/upload' % self.email,
                                data=data, files=files)
        return self.server + '/' + self.email + '/content/' + \
               res.json()['path']

    def download(self, filename):
        pass

