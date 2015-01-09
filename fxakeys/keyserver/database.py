from tinydb import TinyDB, where


_DBS = {}


def init_dbs(keys='/tmp/fxakeys-apikeys.json',
             users='/tmp/fxakeys-userkeys.json'):

    apis = _DBS['api'] = TinyDB(keys)
    if not apis.contains(where('id') == "someapp"):
        apis.insert({'id': "someapp", 'api_key': "12345"})

    users = _DBS['users'] = TinyDB(users)
    return apis, users


def check_api_key(appid, api_key):
    app = _DBS['api'].get(where('id') == appid)
    return app is not None and app.get('api_key') == api_key


def add_api_key(appid, api_key):
    apis = _DBS['api']
    if not apis.contains(where('id') == appid):
        apis.insert({'id': appid, 'api_key': api_key})


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
