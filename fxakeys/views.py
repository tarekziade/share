import json

from bottle import route, request, get, post, HTTPResponse
from fxakeys import database as db


def json(status=200, body=None):
    if body is None:
        body = {}
    body = json.dumps(body)
    raise HTTPResponse(status=status, body=body)


@get('/<email>/app/<appid>/key')
def get_key(email, appid):
    if 'api_key' in request.params:
        if not db.check_api_key(appid, request.params['api_key']):
            return json(503, {'err': 'Wrong api key'})
    else:
        # FxA token
        pass

    key = db.get_user_key(email, appid)
    if key:
        return key

    return json(404, {'err': 'Unknown User'})


@post('/<email>/app/<appid>/key')
def post_key(email, appid):
    db.set_user_key(email, appid, dict(request.POST))
    return {}
