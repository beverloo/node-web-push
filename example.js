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

var crypto = require('crypto');
    curve25519 = require('curve25519'),
    webpush = require('./index');

// Create a public/private key-pair for the "client". In a real implementation
// only the peer's public key would be known to the server.
var privateKey = curve25519.makeSecretKey(crypto.randomBytes(32)),
    publicKey = curve25519.derivePublicKey(privateKey);

// The payload that should be encrypted.
var payload = new Buffer('Hello, world!', 'ascii');

// |encrypted| will have three properties: {localPublic, salt, ciphertext}.
var encrypted = webpush.encrypt({
  peerPublic: publicKey,
  plaintext: payload
});

// |decrypted| will return a Buffer with the decrypted plaintext. Note that this
// would normally be done on another system, so the "peer" in this context are
// the lines above which just encrypted the payload.
var decrypted = webpush.decrypt({
  localPrivate: privateKey,
  peerPublic: encrypted.localPublic,
  salt: encrypted.salt,
  ciphertext: encrypted.ciphertext
});

console.log(decrypted.toString('ascii'));
