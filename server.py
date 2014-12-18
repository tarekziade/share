from bottle import route, run, request, get, post
from collections import defaultdict


_DATABASE = defaultdict(dict)


@get('/<email>/<appname>/key')
def get_key(email, appname):
    return _DATABASE[email][appname]


@post('/<email>/<appname>/key')
def post_key(email, appname):
    _DATABASE[email][appname] = dict(request.POST)
    return {}



run(host='localhost', port=8000)


