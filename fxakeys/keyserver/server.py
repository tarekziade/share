from bottle import run
from fxakeys.keyserver import views       # NOQA
from fxakeys.keyserver.database import init_dbs, add_api_key


def main():
    init_dbs()
    add_api_key("someapp", "12345")
    run(host='localhost', port=8000)


if __name__ == '__main__':
    main()
