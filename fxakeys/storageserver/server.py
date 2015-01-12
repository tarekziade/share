from bottle import run
from fxakeys.storageserver import views       # NOQA


def main():
    run(host='localhost', port=9000)


if __name__ == '__main__':
    main()
