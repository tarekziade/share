from tinydb import TinyDB, where


_DBS = {}


def init_dbs(users='/tmp/fxakeys-userkeys.json'):
    users = _DBS['users'] = TinyDB(users)
    return users


def get_apps(email):
    match = '^%s:.*' % email
    return _DBS['users'].get(where('id').matches(match))


def get_user_key(email, appid):
    id_ = email + ':' + appid
    return _DBS['users'].get(where('id') == id_)


def set_user_key(email, appid, data):
    id_ = data['id'] = email + ':' + appid
    users = _DBS['users']

    if users.contains(where('id') == id_):
        users.update(data, where('id') == id_)
    else:
        users.insert(data)
