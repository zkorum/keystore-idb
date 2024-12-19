# IndexedDB KeyStore

Forked from Fission keystore-idb with a breaking change that adds support for:

- multiple keypairs per key store
- copy keypair within a key store from a key name to another

Also added:
- `function keypairExists(keyName: string): Promise<boolean>`
- `function createOverwriteIfAlreadyExists(writeKeyName: string, exchangeKeyName: string): Promise<KeyStore>`

[![NPM](https://img.shields.io/npm/v/keystore-idb)](https://www.npmjs.com/package/keystore-idb)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/fission-suite/blob/master/LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/b0fabd7e80c6bd2c0c7b/maintainability)](https://codeclimate.com/github/fission-suite/keystore-idb/maintainability)
[![Built by FISSION](https://img.shields.io/badge/⌘-Built_by_FISSION-purple.svg)](https://fission.codes)
[![Discord](https://img.shields.io/discord/478735028319158273.svg)](https://discord.gg/zAQBDEq)
[![Discourse](https://img.shields.io/discourse/https/talk.fission.codes/topics)](https://talk.fission.codes)

In-browser key management with IndexedDB and the Web Crypto API.

Securely store and use keys for encryption, decryption, and signatures. IndexedDB and Web Crypto keep keys safe from malicious javascript.

Supports both RSA (RSASSA-PKCS1-v1_5 & RSA-OAEP) and Elliptic Curves (P-256, P-381 & P-521).

ECC (Elliptic Curve Cryptography) is only available on Chrome. Firefox and Safari do not support ECC and must use RSA.
_Specifically, this is an issue with storing ECC keys in IndexedDB_

## Config

Below is the default config and all possible values
_Note: these are given as primitives, but in Typescript you can use the included enums_

```typescript
const defaultConfig = {
  type: "ecc", // 'ecc' | 'rsa'
  curve: "P-256", // 'P-256' | 'P-384' | 'P-521'
  rsaSize: 2048, // 1024 | 2048 | 4096
  symmAlg: "AES-CTR", // 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
  symmLen: 128, // 128 | 192 | 256
  hashAlg: "SHA-256", // 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
  charSize: 16, // 8 | 16
  storeName: "keystore", // any string
};
```

_Note: if you don't include a crypto "type" (`'ecc' | 'rsa'`), the library will check if your browser supports ECC. If so (Chrome), it will use ECC, if not (Firefox, Safari) it will fall back to RSA._

## Example Usage

```typescript
import keystore from "keystore-idb";

async function run() {
  await keystore.clear();

  const writeKeyName1 = "write-key-1";
  const exchangeKeyName1 = "exchange-key-1";
  const writeKeyName2 = "write-key-2";
  const exchangeKeyName2 = "exchange-key-2";

  const ks1 = await keystore.init({ storeName: "keystore" });
  await ks1.createIfDoesNotExist(writeKeyName1, exchangeKeyName1);
  await ks1.createIfDoesNotExist(writeKeyName2, exchangeKeyName2);

  const msg = "Incididunt id ullamco et do.";

  // exchange keys and write keys are separate because of the Web Crypto API
  const exchangeKey1 = await ks1.publicExchangeKey(exchangeKeyName1);
  const writeKey1 = await ks1.publicWriteKey(writeKeyName1);
  const exchangeKey2 = await ks2.publicExchangeKey(exchangeKeyName2);

  // these keys get exported as strings
  console.log("exchangeKey1: ", exchangeKey1);
  console.log("writeKey1: ", writeKey1);
  console.log("exchangeKey2: ", exchangeKey2);

  const sig = await ks1.sign(msg, writeKeyName1);
  const valid = await ks1.verify(msg, sig, writeKey1);
  console.log("sig: ", sig);
  console.log("valid: ", valid);

  const cipher = await ks1.encrypt(msg, exchangeKey2, exchangeKeyName1);
  const decipher = await ks1.decrypt(cipher, exchangeKeyName2, exchangeKey1);
  console.log("cipher: ", cipher);
  console.log("decipher: ", decipher);
}

const newExchangeKeyName1 = "new-exchange-key-1";
const newWriteKeyName1 = "new-write-key-1";
await ks1.copyKeypair(exchangeKeyName1, newExchangeKeyName1);
await ks1.copyKeypair(writeKeyName1, newWriteKeyName1);
// The above two commands made writeKey1 and exchangeKey1 available from new keynames.

run();
```

## Development

```shell
# install dependencies
yarn

# run development server
yarn start

# build
yarn build

# test
yarn test

# test w/ reloading
yarn test:watch

# publish (run this script instead of npm publish!)
./publish.sh
```
