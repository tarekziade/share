from bottle import run
from fxakeys import views
from fxakeys.database import init_dbs


def main():
    apis, users = init_dbs()
    add_api_key("someapp", "12345")

    run(host='localhost', port=8000)


if __name__ == '__main__':
    main()
