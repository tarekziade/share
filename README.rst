Share
=====

Experiments on a key directory


Definitions
===========

- **kBr** - kBr is derived from FxA's kB key using HKDF, specifically for an app



User stories
============

Prerequisite - publish keys to the key Directory
------------------------------------------------

Steps:

1. connect to FxA and retrieve kBr for the "Password Manager" app
2. generate a random public/private key pair
3. encrypt the private key using kBr and a nonce
4. publish the public key, the nonce and the encrypted private key in the key directory



App 1 - Shared passwords
------------------------

**As a user I want to be able to share my Netflix and Hulu credentials with my
wife and kids.**

Steps to share the credentials:

1. list the emails of my wife and kids.
2. for each email, get the public key associated to the 'shared password' app
3. for each email, encrypt the Netflix password using the public key
4. post each encrypted version to the cloud


Steps to get back the credentials:

1. retrieve the encrypted data
2. get back the public and encrypted privated key fron the user directory
3. get back kBr from FxA
4. decrypt the private key using kBr
5. use the private key to decrypt the Netflix password



Server API
==========

The server API is served under https, so no header or query options
are revealed through the transport.

The server maintains internally a list of applications. There
are no global public API to list, modify, add or delete applications.

The API can be accessed by **applications** and by **users**.


Application registration and access
-----------------------------------

In order to interact with the service, an application must be
added manually to the system. The registration process is out
of the scope of this proposal.

An application is registered under a short identifier that
will be used in the endpoints.

Application that are registered get an API key they can
use to query the server. They are only able to retrieve the
public keys for their users.

The API key is passed to the endpoint with an **api_key**
query option.

The application is responsible to keep its directory
identifier and pass it to users that need it.


Users registration and access
-----------------------------

The service acts as an FxA OAuth relier. Users that are
connecting this way are automatically registered on their
first call to the service.

An authenticated user is able to:

- publish and revoke their keys for a given application
- get the public key of other users if they use the same application
- list the applications they are registered to.


APIs
----

GET /<email>/app/<appid>/key
############################

**Requires an FxA Oauth authentication or an API key that matches <appid>**

Returns the keys of a given user for a given app.
The returned value is a json mapping containing:

- pubKey: the public key
- encPrivKey*: the encrypted private key
- nonce*: the nonce used to encrypt the private key


* The encPrivKey and nonce fields are sent back only if the
authenticated user owns the email.


GET /<email>/app
################

**Requires an FxA Oauth authentication that matches <email>**

Used to retrieve the list of apps a user is registered to.
Returns a mapping containing a single key:

- apps: a list of apps identifiers


POST /<email>/<appid>/key
#########################

**Requires an FxA Oauth authentication that matches <email>**

Used to post a keypair to the server. The POST body is a Json
mapping containing:

- pubKey: the public key
- encPrivKey: the encrypted private key
- nonce: the nonce used to encrypt the private key


Full example
============

XXX

