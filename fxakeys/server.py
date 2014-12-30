from bottle import route, run, request, get, post, HTTPError
from collections import defaultdict


_DATABASE = defaultdict(dict)
_APP_KEYS = {'someapp': '12345'}


@get('/<email>/app/<appid>/key')
def get_key(email, appid):
    if 'api_key' in request.params:
        if _APP_KEYS.get(appid) != request.params['api_key']:
            raise HTTPError(503, 'Wrong api key')
    else:
        # FxA token
        pass

    return _DATABASE[email][appid]


@post('/<email>/app/<appid>/key')
def post_key(email, appid):
    _DATABASE[email][appid] = dict(request.POST)
    return {}



run(host='localhost', port=8000)


