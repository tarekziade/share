from bottle import run
from fxakeys.keyserver import views       # NOQA
from fxakeys.keyserver.database import init_dbs


def main():
    init_dbs()
    run(host='localhost', port=8000)


if __name__ == '__main__':
    main()
