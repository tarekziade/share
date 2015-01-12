import json

from bottle import request, get, post, HTTPResponse
from fxakeys.utils import fxa_auth


@get('/<email>/<path>')
@fxa_auth
def get_content(email, path):
    return {}
