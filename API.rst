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


\* The encPrivKey and nonce fields are sent back only if the
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

