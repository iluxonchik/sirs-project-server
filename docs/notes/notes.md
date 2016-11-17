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