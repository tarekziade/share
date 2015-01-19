import json as _json

from bottle import request, HTTPResponse
from fxakeys.fxaoauth import verify_oauth_token


def verify_fxa_token(token):
    return verify_oauth_token(token)["user"]


def json(status=200, body=None):
    if body is None:
        body = {}
    body = _json.dumps(body)
    raise HTTPResponse(status=status, body=body)


def _check_fxa():
    auth = request.headers.get('Authorization', '')
    try:
        token_type, token = auth.split()
        assert token_type == 'Bearer'
    except (ValueError, AssertionError):
        msg = auth == '' and 'Unauthorized' or 'Bad Authentication'
        json(503, {'err': msg})

    if not verify_fxa_token(token):
        json(503, {'err': 'Bad Token'})


def fxa_auth(func):
    def _fxa_auth(*args, **kw):
        _check_fxa()
        return func(*args, **kw)
    return _fxa_auth
