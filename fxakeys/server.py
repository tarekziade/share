from collections import defaultdict
import json

from bottle import route, run, request, get, post, HTTPResponse
from fxakeys.database import (init_dbs, check_api_key, get_user_key,
                              set_user_key, add_api_key)


@get('/<email>/app/<appid>/key')
def get_key(email, appid):
    if 'api_key' in request.params:
        if not check_api_key(appid, request.params['api_key']):
            err = {'err': 'Wrong api key'}
            raise HTTPResponse(status=503, body=json.dumps(err))
    else:
        # FxA token
        pass

    key = get_user_key(email, appid)
    if key:
        return key

    err = {'err': 'Unknown User'}
    raise HTTPResponse(status=404, body=json.dumps(err))


@post('/<email>/app/<appid>/key')
def post_key(email, appid):
    set_user_key(email, appid, dict(request.POST))
    return {}



def main():
    apis, users = init_dbs()
    add_api_key("someapp", "12345")

    run(host='localhost', port=8000)


if __name__ == '__main__':
    main()
