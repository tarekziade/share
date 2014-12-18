import requests
import nacl
import nacl.utils
import nacl.secret
import binascii
from nacl.public import PrivateKey, Box


email = 'tarek@ziade.org'
appname = 'someapp'
appkey = '12345'
root = 'http://localhost:8000/'
key_url = root + email + '/' + appname + '/key?appkey=' + appkey
# secret key, we got from FxA
kBr = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)



def get_key(email, appname, appkey):
    result = requests.get(key_url)
    if result.status_code == 404:
        return None
    data = result.json()
    box = nacl.secret.SecretBox(kBr)
    nonce = binascii.unhexlify(data['nonce'])
    encrypted_private_key = nacl.utils.EncryptedMessage.fromhex(data['encPrivKey'])
    private_key = box.decrypt(encrypted_private_key)
    private_key = PrivateKey(private_key)
    return private_key, private_key.public_key


def post_key(email, appname, pub_key, enc_priv_key, nonce, appkey):
    options = {'pubKey': pub_key, 'encPrivKey': enc_priv_key,
               'nonce': nonce}
    result = requests.post(key_url, data=options)
    if result.status_code != 200:
        raise Exception('Failed')



def generate_keys():
    # generate random private/public key
    private_key = PrivateKey.generate()
    return private_key, private_key.public_key


def encrypt_key(key, secret):
    # encrypt the private key with our secret
    box = nacl.secret.SecretBox(secret)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(key.encode(), nonce)
    encrypted = binascii.hexlify(encrypted)
    return encrypted, binascii.hexlify(nonce)


priv, pub = generate_keys()
pub = binascii.hexlify(pub.encode())
enc_priv, nonce = encrypt_key(priv, kBr)


post_key(email, appname, pub, enc_priv, nonce, appkey)
print(get_key(email, appname, appkey))

