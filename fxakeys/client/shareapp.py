import os
import argparse

from fxakeys.crypto import _HEX_ENC_CHUNK, enc_size
from fxakeys.client.storage import UserStorage
from fxakeys.client.keys import AppUser


class _Reader(object):
    def __init__(self, storage, sender, filename):
        self.start = self.end = 0
        self.storage = storage
        self.sender = sender
        self.filename = filename
        self._read = storage.get_shared_content

    def read(self, size=_HEX_ENC_CHUNK):
        if self.start == 0:
            self.end = size - 1
        range = self.start, self.end
        try:
            return self._read(self.sender, self.filename, range)
        finally:
            self.start = self.end + 1
            self.end = self.start + size - 1


class _Chunker(object):
    def __init__(self, user, filepath, target):
        self.user = user
        self.filepath = filepath
        self.target = target
        self.len = enc_size(os.path.getsize(filepath))
        self.stream = user.stream_encrypt(open(filepath), target)

    def __iter__(self):
        return self

    def next(self):
        return self.stream.next()


def share():
    """Share a file with another user
    """
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
    chunker = _Chunker(user, args.file, args.target)
    storage.share_content(args.target, chunker, filename)
    print('Shared!')


def get():
    parser = argparse.ArgumentParser(
        description='Get a file shared by someone.')
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

    if os.path.exists(filename):
        raise IOError('File already exist')

    reader = _Reader(storage, args.sender, filename)

    with open(filename, 'w') as f:
        for chunk in user.stream_decrypt(reader, args.sender):
            f.write(chunk)

    print(filename)
