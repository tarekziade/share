import json

from bottle import request, get, post, HTTPResponse
from fxa.oauth import Client
from fxa.errors import ClientError
from fxakeys import database as db


def verify_fxa_token(token):
    fxa = Client()
    try:
        profile = fxa.verify_token(token)
    except ClientError:
        return None
    return profile["user"]


def _json(status=200, body=None):
    if body is None:
        body = {}
    body = json.dumps(body)
    raise HTTPResponse(status=status, body=body)


@get('/<email>/app/<appid>/key')
def get_key(email, appid):
    if 'api_key' in request.params:
        # API key auth
        if not db.check_api_key(appid, request.params['api_key']):
            return _json(503, {'err': 'Wrong api key'})
    else:
        # FxA token
        auth = request.headers.get('Authorization', '')
        try:
            token_type, token = auth.split()
            assert token_type == 'Bearer'
        except (ValueError, AssertionError):
            msg = auth == '' and 'Unauthorized' or 'Bad Authentication'
            return _json(503, {'err': msg}

        if not verify_fxa_token(token):
            return _json(503, {'err': 'Bad Token'}

    key = db.get_user_key(email, appid)
    if key:
        return key

    return _json(404, {'err': 'Unknown User'})


@post('/<email>/app/<appid>/key')
def post_key(email, appid):
    db.set_user_key(email, appid, dict(request.POST))
    return {}
