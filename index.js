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

// Size of the AES-128-GCM authentication tag, in bytes.
const AUTHENTICATION_TAG_SIZE = 16;

// The default record size. Web Push messages must be encrypted in a single
// record, so messages larger than this should explictly set the |rs|.
const DEFAULT_RECORD_SIZE = 4096;

// Identifier of the key to use with Martin's HTTP Encrypted Encoding package.
const KEY_IDENTIFIER = '__webpush_key';

// Length of a Curve25519 private-key to generate, in bytes.
const KEY_LENGTH = 32;

// Length of the HKDF salt to generate, in bytes.
const SALT_LENGTH = 16;

module.exports = {
  decrypt: function(params) {
    if (!params.localPrivate || params.localPrivate.length != KEY_LENGTH)
      throw new Error('A ' + KEY_LENGTH + '-byte `localPrivate` must be provided.');

    if (!params.peerPublic || params.peerPublic.length != KEY_LENGTH)
      throw new Error('A ' + KEY_LENGTH + '-byte `peerPublic` must be provided.');

    if (!params.salt || params.salt.length != SALT_LENGTH)
      throw new Error('A ' + SALT_LENGTH + '-byte `salt` must be provided.');

    if (!params.ciphertext || !(params.ciphertext instanceof Buffer))
      throw new Error('A ciphertext must be provided in the `ciphertext` property.');

    params.rs = params.rs || DEFAULT_RECORD_SIZE;

    if (params.ciphertext.length >= params.rs + AUTHENTICATION_TAG_SIZE + 1)
      throw new Error('The `ciphertext` must only consist of a single record.');

    // Derive the shared secret between the keys.
    var sharedSecret = curve25519.deriveSharedSecret(params.localPrivate,
                                                     params.peerPublic);

    ece.saveKey(KEY_IDENTIFIER, sharedSecret);

    // Now actually decrypt the |params.ciphertext| using HTTP Encrypted Encoding.
    return ece.decrypt(params.ciphertext, {
      keyid: KEY_IDENTIFIER,
      salt: urlbase64.encode(params.salt),
      rs: params.rs
    });
  },

  encrypt: function(params) {
    if (!params.peerPublic || params.peerPublic.length != KEY_LENGTH)
      throw new Error('A ' + KEY_LENGTH + '-byte `peerPublic` must be provided.');

    if (!params.plaintext || !(params.plaintext instanceof Buffer))
      throw new Error('A plaintext must be provided in the `plaintext` property.');

    // Create an ephemeral public/private key-pair for the encryption.
    var localPrivate = curve25519.makeSecretKey(crypto.randomBytes(KEY_LENGTH)),
        localPublic = curve25519.derivePublicKey(localPrivate);

    // Derive the shared secret between the keys.
    var sharedSecret = curve25519.deriveSharedSecret(localPrivate,
                                                     params.peerPublic);

    // Create a 16-byte salt so that the client's public key can be reused.
    var salt = crypto.randomBytes(SALT_LENGTH);

    var rs = Math.max(params.plaintext.length + 1, DEFAULT_RECORD_SIZE);

    ece.saveKey(KEY_IDENTIFIER, sharedSecret);

    // Now actually encrypt the |params.plaintext| using HTTP Encrypted Encoding.
    var ciphertext = ece.encrypt(params.plaintext, {
      keyid: KEY_IDENTIFIER,
      salt: urlbase64.encode(salt),
      rs: rs
    });

    return {
      localPublic: localPublic,
      salt: salt,
      rs: rs,
      ciphertext: ciphertext
    };
  }
};
