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


def _check_fxa():
    auth = request.headers.get('Authorization', '')
    try:
        token_type, token = auth.split()
        assert token_type == 'Bearer'
    except (ValueError, AssertionError):
        msg = auth == '' and 'Unauthorized' or 'Bad Authentication'
        _json(503, {'err': msg})

    if not verify_fxa_token(token):
        _json(503, {'err': 'Bad Token'})



def fxa_auth(func):
    def _fxa_auth(*args, **kw):
        _check_fxa()
        return func(*args, **kw)
    return _fxa_auth


@get('/<email>/apps')
@fxa_auth
def get_apps(email):
    key = db.get_user_key(email, appid)
    if key:
        return key

    return _json(404, {'err': 'Unknown User'})


@get('/<email>/apps/<appid>/key')
def get_key(email, appid):
    _check_fxa()

    key = db.get_user_key(email, appid)
    if key:
        return key

    return _json(404, {'err': 'Unknown User'})


@post('/<email>/apps/<appid>/key')
@fxa_auth
def post_key(email, appid):
    db.set_user_key(email, appid, dict(pubKey=request.POST['pubKey']))
    return {}
