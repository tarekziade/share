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


