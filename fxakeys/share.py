import requests
import nacl
import nacl.utils
import nacl.secret
import binascii
from nacl.public import PrivateKey
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def hkdf_expand(key, info, salt=None):
    backend = default_backend()
    salt = salt or os.urandom(len(key))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info,
                backend=backend)
    return hkdf.derive(key), salt


def get_key(email, appid, api_key):
    result = requests.get(key_url + '?api_key=' + api_key)
    if result.status_code in (404, 503):
        return None
    data = result.json()
    box = nacl.secret.SecretBox(kBr)
    return data['pubKey']


def post_key(email, appid, pub_key, oauth_token):
    options = {'pubKey': pub_key}
    result = requests.post(key_url, data=options)
    if result.status_code != 200:
        raise Exception('Failed')


# let's sign into FxA and grab kA, kB
# XXX in the real world we'll use an oauth relier flow
# but for now we're using a direct fxa login
from fxa.core import Client
from getpass import getpass

FXA_OAUTH_URI = 'https://oauth-stable.dev.lcip.org'
FXA_API_URI = 'https://stable.dev.lcip.org/auth'


client = Client(FXA_API_URI)
email = raw_input('FxA email: ')
password = getpass('FxA password: ')
appid = 'someapp'
api_key = '12345'
root = 'http://localhost:8000/'
key_url = root + email + '/app/' + appid + '/key'

print('Login into FxA')
session = client.login(email, password, keys=True)
print('Fetching the keys')
kA, kB = session.fetch_keys(stretchpwd=password)

# kB key derived for our app
print('Creating kBr')
__, kBr = hkdf_expand(kB, b"identity.mozilla.com/picl/v1/keys/relier/SharingApp")

# let's generate a public and a private key pair
print('Generating a key/pair')
priv = PrivateKey(private_key)
pub = binascii.hexlify(priv.public_key.encode())

# get a long-lived oauth token
fxa_client_id = ''
fxa_client_secret = ''


from fxa.oauth import Client as OAuthClient

oauth_client = OAuthClient(server_url=FXA_OAUTH_URI)
oauth_token = oauth_client.trade_code(fxa_client_id, fxa_client_secret,
                                      session.token)

# posting the key to the user directory service
print('Posting the Key pair to the directory')
post_key(email, appid, pub, oauth_token)

# getting the key out of the user directory service
print('Fetching the pubKey from the directory')

print(get_key(email, appid, api_key))
