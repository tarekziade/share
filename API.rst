Key Server API
==============

The server URLs semantics is mostly REST semantics ::

  https://<server>/<api path>/<version>/<further instructions>

The rest of this document only presents the <further instructions> part
and makes the assumption that the API is served behind an ssl connection
that protects the requests header, body and query options during transport,
as well as the responses content.

The proposed service is implemented as an FxA content provider, so it accepts
Bearer Tokens with the **keys:** scope as a form of authentication.


GET /<email>/app/<appid>/key
############################

- scope: keys
- authentication: FxA Oauth token
- authorization: any FxA user with a valid OAuth token and
  with an existing key pair for this app.

Returns the keys of a given user for a given app.
The returned value is a json mapping containing:

- pubKey: the public key
- encPrivKey*: the encrypted private key
- nonce*: the nonce used to encrypt the private key

\* The encPrivKey and nonce fields are sent back only
if the connected user owns the <email>.


GET /<email>/app
################

- scope: keys
- authentication: FxA Oauth token
- authorization: the FxA user owning the e-mail

Used to retrieve the list of apps a user is registered to.
Returns a mapping containing a single key:

- apps: a list of apps identifiers


POST /<email>/<appid>/key
#########################

- scope: keys:write
- authentication: FxA Oauth token
- authorization: the FxA user owning the e-mail

Used to post a keypair to the server. The POST body is a Json
mapping containing:

- pubKey: the public key
- encPrivKey: the encrypted private key
- nonce: the nonce used to encrypt the private key

DELETE /<email>/<appid>/key
###########################

- scope: keys:write
- authentication: FxA Oauth token
- authorization: the FxA user owning the e-mail

Removes the key.
