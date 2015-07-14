/**
 * Copyright 2015 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var urlbase64 = require('urlsafe-base64'),
    crypto = require('crypto'),
    curve25519 = require('curve25519'),
    ece = require('encrypted-content-encoding');

// Identifier of the key to use with Martin's HTTP Encrypted Encoding package.
const KEY_IDENTIFIER = '__webpush_key';

// Length of a Curve25519 private-key to generate, in bytes.
const KEY_LENGTH = 32;

// Length of the HKDF salt to generate, in bytes.
const SALT_LENGTH = 16;

module.exports = {
  decrypt: function(params) {
    if (!params.localPrivate || params.localPrivate.length != KEY_LENGTH)
      throw new Error('A ' + KEY_LENGTH + '-byte localPrivate must be provided.');

    if (!params.peerPublic || params.peerPublic.length != KEY_LENGTH)
      throw new Error('A ' + KEY_LENGTH + '-byte peerPublic must be provided.');

    if (!params.salt || params.salt.length != SALT_LENGTH)
      throw new Error('A ' + SALT_LENGTH + '-byte salt must be provided.');

    if (!params.data || !(params.data instanceof Buffer))
      throw new Error('A ciphertext must be provided in the data property.');

    // Derive the shared secret between the keys.
    var sharedSecret = curve25519.deriveSharedSecret(params.localPrivate,
                                                     params.peerPublic);

    ece.saveKey(KEY_IDENTIFIER, sharedSecret);

    // Now actually decrypt the |params.data| using HTTP Encrypted Encoding.
    return ece.decrypt(params.data, {
      keyid: KEY_IDENTIFIER,
      salt: urlbase64.encode(params.salt)
    });
  },

  encrypt: function(params) {
    if (!params.peerPublic || params.peerPublic.length != KEY_LENGTH)
      throw new Error('A ' + KEY_LENGTH + '-byte peerPublic must be provided.');

    if (!params.data || !(params.data instanceof Buffer))
      throw new Error('A plaintext must be provided in the data property.');

    // Create an ephemeral public/private key-pair for the encryption.
    var localPrivate = curve25519.makeSecretKey(crypto.randomBytes(KEY_LENGTH)),
        localPublic = curve25519.derivePublicKey(localPrivate);

    // Derive the shared secret between the keys.
    var sharedSecret = curve25519.deriveSharedSecret(localPrivate,
                                                     params.peerPublic);


    // Create a 16-byte salt so that the client's public key can be reused.
    var salt = crypto.randomBytes(SALT_LENGTH);

    ece.saveKey(KEY_IDENTIFIER, sharedSecret);

    // Now actually encrypt the |params.data| using HTTP Encrypted Encoding.
    var ciphertext = ece.encrypt(params.data, {
      keyid: KEY_IDENTIFIER,
      salt: urlbase64.encode(salt)
    });

    return {
      localPublic: localPublic,
      salt: salt,
      ciphertext: ciphertext
    };
  }
};
