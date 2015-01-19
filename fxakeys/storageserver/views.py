import os
from bottle import request, get, post, static_file
from fxakeys.utils import fxa_auth

_ROOT = '/tmp'


# permissions
# shold allow only the owner of the fils *or* the target of a shared
# content
#
# XXX add a chunked version for big files
@get('/<email>/content/<filepath:path>')
@fxa_auth
def get_content(email, filepath):
    root = os.path.join(_ROOT, email)

    # XXX security
    if not os.path.exists(root):
        os.makedirs(root)

    target = os.path.join(root, filepath)
    if os.path.isdir(target):
        def _item(item):
            fullname = os.path.join(target, item)
            type_ = os.path.isdir(fullname) and 'directory' or 'file'
            return {'type': type_, 'name': item}

        return {'items': [_item(item) for item in os.listdir(target)]}

    return static_file(filepath, root=root)


@post('/<email>/upload')
@fxa_auth
def post_content(email):
    root = os.path.join(_ROOT, email)
    # XXX security
    if not os.path.exists(root):
        os.makedirs(root)

    folder_path = request.headers['folder_id'].lstrip('/')

    target_dir = os.path.join(root, folder_path)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    filename = request.headers['filename']

    # XXX security
    fullpath = os.path.join(target_dir, filename)

    content_range = request.headers['Content-Range']

    start = int(content_range.split(' ')[1].split('-')[0])
    mode = start == 0 and 'w' or 'a+'

    with open(fullpath, mode) as f:
        if mode == 'a+':
            f.seek(start)
        f.write(request.body.read())

    # should return a 206 here
    return {'path': os.path.join(folder_path, filename)}


@get('/<email>/content')
@fxa_auth
def get_root(email):
    root = os.path.join(_ROOT, email)

    # XXX security
    if not os.path.exists(root):
        os.makedirs(root)

    return {'items': os.listdir(root)}
