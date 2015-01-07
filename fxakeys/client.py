# uses https://github.com/mozilla/PyFxA/tree/rfk/assertion-and-oauth-helpers
#
import fxa.core
import json
import os

from fxa.oauth import Client as OAuthClient
from fxa.core import Client


EMAIL = os.environ.get('FXA_USER', "tarek@mozilla.com")
PASSWORD = os.environ.get('FXA_PASSWORD')

CLIENT_ID = "021fd64aa9661fa1"
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')

AUTH_SERVER = "https://stable.dev.lcip.org/auth"
OAUTH_SERVER = "https://oauth-stable.dev.lcip.org"

# The relier kicks of the oauth dance by redirecting to this URL:

oauth_client = OAuthClient(CLIENT_ID, CLIENT_SECRET, OAUTH_SERVER)
redirect_url = oauth_client.get_redirect_url()

print "REDIRECT URL:", redirect_url

# On the redirected page, javascript from fxa-content-server prompt for the
# user's password, generate an assertion, use it to authorize a short-lived
# code, and redirects back to the relier to pass it the code:

session = Client(server_url=AUTH_SERVER).login(EMAIL, PASSWORD)
print "SESSION TOKEN", session.token

assertion = session.get_identity_assertion(OAUTH_SERVER)
code = oauth_client.authorize_code(assertion, "profile", CLIENT_ID)

print "OAUTH CODE:", code

# The relier receives the code and trades it for a long-lived token:
token = oauth_client.trade_code(code)

print "OAUTH TOKEN:", token

# It can use the token for its own authentication purposes, or it can
# pass the token to a service-provider to access services on the user's
# behalf.  Either way, it needs to verify the token and its scopes like so:

data = oauth_client.verify_token(token, scope="profile")

print "TOKEN DATA:", json.dumps(data, indent=4)



