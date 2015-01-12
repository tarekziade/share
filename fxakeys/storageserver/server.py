from bottle import run
from fxakeys.storageserver import views       # NOQA
from fxakeys.storageserver.database import init_dbs


def main():
    init_dbs()
    run(host='localhost', port=8000)


if __name__ == '__main__':
    main()
