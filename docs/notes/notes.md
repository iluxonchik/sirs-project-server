# Encryption/Decryption

## Decision Overview

* Use AES 128 bit for file encryption
* Use SHA-256 HMAC for integrity

Note, we're using [Fernet](https://github.com/fernet/spec/blob/master/Spec.md),
it already provides integrity and freshness (if needed), so we won't have
to implement the integrity-checking part. It used **SHA-256 HMAC**. 
Basically, the output of the [.encrypt()](https://cryptography.io/en/latest/fernet/#cryptography.fernet.Fernet.encrypt) returns a base64-encoded result
which besides the ciphertext contains additional info which is used to provide 
**confidentiality**, **authenticity** and **integrity** (since Fernet uses 
[Authenticated Cryptography](https://en.wikipedia.org/wiki/Authenticated_encryption)).

## Decisions Justification

For **integrity** should you **MAC-Then-Encrypt** or **Encrypt-Then-MAC**?
- **Encrypt-Then-Mac** [justification](http://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac)

For integrity **SHA1** or **SHA-256**? 
- **SHA-256**, SHA-1 would be fine for checking downloaded files, but we want to
make sure that the encrypted files have not been tampered with. That way we're also
future-proofing. [GnuPG moved to SHA-256 in 2012](https://lists.gnupg.org/pipermail/gnupg-users/2016-January/055057.html)

# Application

* easily configurable through `settings.py`
* `run.py` starts up the server
* throughout all the application, crypto random generators are used (Python's `os.urnandom()`)

# User Managment

* sqlite3 stores user/password combination
* protection agaisnt SQL injections, by using `?` placeholders and passing the values to `execute()`

## Token Managment

* each `User` instance has an associated token manager
* if a token or the private key gets compromised, simply regenerate the key that encrypts the token (*i.e.* set token manager attr in `User` to a new instance or call TokenManager.generate_new())
* tokens are encrypted with AES-256 in CBC mode with an iv of 128bit.
* tokens have guarantee of integrity (provided by [Cryptography](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/))
* token blacklist can be easily implemented by adding a list to the TokenManger class
