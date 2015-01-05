FxA Key Server API
==================

The server URLs semantics is mostly REST semantics ::

  https://<server>/<api path>/<version>/<further instructions>

The rest of this document only presents the <further instructions> part
and makes the assumption that the API is served behind an ssl connection
that protects the requests header, body and query options during transport,
as well as the responses content.

The proposed service is implemented as an FxA content provider, so
it accepts Bearer Tokens with the **keys:** scope as a form of
authentication.

Users are identified with their **FxA uid** obtained from the profile server
and transmitted to teh 3rd party application.

See https://github.com/mozilla/fxa-profile-server/blob/master/docs/API.md#get-v1uid


GET /<uid>/keys
###############

* scope: keys
* authentication: no authentication **or** an FxA OAuth token matching <uid>

Returns the keys of a given user for a given app. The returned value is
a json mapping containing:

- pubKey: the public key
- encPrivKey*: the encrypted private key
- nonce*: the nonce used to encrypt the private key

\* The encPrivKey and nonce fields are sent back only if the
authentication is done by the user owning the <uid>.


POST /<uid>/keys
################

* scope: keys:write
* authentication: an FxA OAuth token matching <uid>


Used to post a keypair to the server. The POST body is a Json
mapping containing:

- pubKey: the public key
- encPrivKey: the encrypted private key
- nonce: the nonce used to encrypt the private key


DELETE /<uid>/key
###########################

* scope: keys:write
* authentication: an FxA OAuth token matching <uid>


Removes the key pair from the server.
