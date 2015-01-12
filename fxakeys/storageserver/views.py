import json
import os

from bottle import request, get, post, HTTPResponse, static_file
from fxakeys.utils import fxa_auth

_ROOT = '/tmp'


@get('/<email>/content/<filepath:path>')
@fxa_auth
def get_content(email, filepath):
    root = os.path.join(_ROOT, email)

    # XXX security
    if not os.path.exists(root):
        os.makedirs(root)

    target = os.path.join(root, filepath)
    if os.path.isdir(target):
        return {'items': os.listdir(target)}

    return static_file(filepath, root=root)


@post('/<email>/upload')
@fxa_auth
def post_content(email):
    root = os.path.join(_ROOT, email)
    # XXX security
    if not os.path.exists(root):
        os.makedirs(root)

    folder_path = request.params['folder_id'].lstrip('/')
    target_dir = os.path.join(root, folder_path)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    filename, file_ = request.files.items()[0]
    # XXX security
    fullpath = os.path.join(target_dir, filename)
    file_.save(fullpath, overwrite=True)

    return {'path': os.path.join(folder_path, filename)}


@get('/<email>/content')
@fxa_auth
def get_root(email):
    root = os.path.join(_ROOT, email)

    # XXX security
    if not os.path.exists(root):
        os.makedirs(root)

    return {'items': os.listdir(root)}
