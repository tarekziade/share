from bottle import request, get, post
from fxakeys.keyserver import database as db
from fxakeys.utils import fxa_auth, json as _json


@get('/<email>/apps')
@fxa_auth
def get_apps(email):
    apps = db.get_apps(email)
    if not apps:
        return _json(404, {'err': 'Unknown User'})
    return {'apps': [app['id'] for app in apps]}


@get('/<email>/apps/<appid>/key')
@fxa_auth
def get_key(email, appid):
    # XXX todo : if the connected user does not
    # own that email, do not send back encPrivKey
    key = db.get_user_key(email, appid)
    if key:
        return key

    return _json(404, {'err': 'Unknown User'})


@post('/<email>/apps/<appid>/key')
@fxa_auth
def post_key(email, appid):
    db.set_user_key(email, appid, dict(request.POST))
    return {}
