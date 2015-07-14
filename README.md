# Web Push Payload Encryption (Node.js)
This package provides an implementation of [IETF Web Push encryption draft](https://tools.ietf.org/html/draft-thomson-webpush-encryption-00), but uses Curve25519 as the ECDH curve rather than the proposed P-256.

Note that this package is not meant to be used in production, and has thus not been published on NPM.

## webpush.encrypt(params)
  * `params.peerPublic`: 32-byte Curve25519 ECDH public key of the peer.
  * `params.data`: Buffer holding the to-be-encrypted plaintext.

Returns an object with three properties: `localPublic`, the 32-byte Curve25519 ECDH ephemeral public key of the server, `salt`, the 16-byte cryptograhically secure random salt and `ciphertext`, the encrypted ciphertext.

## webpush.decrypt(params)
  * `params.localPrivate`: 32-byte Curve25519 ECDH local private key.
  * `params.peerPublic`: 32-byte Curve25519 ECDH public key of the peer.
  * `params.salt`: 16-byte salt used for the encryption.
  * `params.data`: Buffer holding the encrypted ciphertext.

Returns a Buffer with the decrypted plaintext.

## TODO
  * Upgrade to [draft-thomson-webpush-encryption-01](https://tools.ietf.org/html/draft-thomson-webpush-encryption-01).
  * Include some tests to verify the implementation.
