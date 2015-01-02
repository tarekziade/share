from collections import defaultdict
import json

from bottle import route, run, request, get, post, HTTPResponse
from tinydb import TinyDB, where


DBS = {}



@get('/<email>/app/<appid>/key')
def get_key(email, appid):
    if 'api_key' in request.params:
        app = DBS['api'].get(where('id') == appid)
        if app is None or app.get('api_key') != request.params['api_key']:
            err = {'err': 'Wrong api key'}
            raise HTTPResponse(status=503, body=json.dumps(err))
    else:
        # FxA token
        pass

    user = DBS['users'].get(where('email') == email)
    if user:
        return user

    err = {'err': 'Unknown User'}
    raise HTTPResponse(status=404, body=json.dumps(err))


@post('/<email>/app/<appid>/key')
def post_key(email, appid):
    data = dict(request.POST)
    data['email'] = email
    data['appid'] = appid
    users = DBS['users']
    if users.contains(where('email') == email):
        DBS['users'].update(data, where('email') == email)
    else:
        DBS['users'].insert(data)
    return {}



def main():
    apis = DBS['api'] = TinyDB('/tmp/fxakeys-apikeys.json')
    if not apis.contains(where('id') == "someapp"):
        appis.insert({'id': "someapp", 'api_key': "12345"})

    DBS['users'] = TinyDB('/tmp/fxakeys-userkeys.json')
    run(host='localhost', port=8000)


if __name__ == '__main__':
    main()
