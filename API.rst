Key Server API
==============

The server URLs semantics is mostly REST semantics ::

  https://<server>/<api path>/<version>/<further instructions>

The rest of this document only documents the further instructions part
and make the assumption that the API is served behind an ssl connection
that protects the requests header, body and query options during transport,
as well as the responses content.

The proposed API can be accessed by **applications** and by **users**.

An **application** is a third party service that interacts with the key
server in order to obtain its users keys.

A **user** is any application that posess a valid FxA token.


Application registration and access
-----------------------------------

The server maintains internally a list of applications. There
are no global public API to list, modify, add or delete applications.


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

The application is responsible to keep its identifier and
pass it to users that need it.


Users registration and access
-----------------------------

The service acts as an FxA OAuth relier. Users that are
connecting this way are automatically registered on their
first call to the service.

An authenticated user is able to:

- publish and revoke their keys for a given application
- list the applications they are registered to.


APIs
----

GET /<email>/app/<appid>/key
############################

**Requires an FxA Oauth authentication that matches <email>
or an API key that matches <appid>**

Returns the keys of a given user for a given app.
The returned value is a json mapping containing:

- pubKey: the public key
- encPrivKey*: the encrypted private key
- nonce*: the nonce used to encrypt the private key


\* The encPrivKey and nonce fields are sent back only if the
authentication is done by the user owning the email.


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

DELETE /<email>/<appid>/key
###########################

**Requires an FxA Oauth authentication that matches <email>**

Removes the key.
