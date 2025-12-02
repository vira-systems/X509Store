Vira X509Store
=======================
**A service for web users to communicate with smart cards, USB hard-tokens, and other types of security module that support PKCS#11.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
## Overview

The everyday need of web users to perform digital signatures and other cryptographic operations using X.509 certificates led to the creation of a service that could communicate with smart cards and other types of cryptographic hardware on different platforms and provide cryptographic capabilities to developers, while meeting the needs of web users for signing and other cryptographic operations using hard tokens.

For this purpose, several open source projects were used, including [Bouncy Castle](https://www.bouncycastle.org/) (nuget package), which supports cryptography and cryptographic protocols, and [Pkcs11Interop.X509Store](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store) (source code with some modification), which simplifies the integration of PKCS#11 into .NET applications.

I would like to express my special thanks to the contributors of both projects. Especially to [Jaroslav Imrich](https://github.com/jariq), whose various projects helped me to better and deeper understand the PKCS#11 standard.

## Features

#### General Features

- Token Info, returns PKCS#11 token information.
- Mechanism Infos, returns supported mechanism infos for the usable slot.
- Store Certificates, finds certificates only in current user store.
- Token Certificates, finds certificates on hardware token only.
- Token Certificates From Store, finds certificates combining token and user store.

#### PKCS#1 Features

- Encrypt, encrypts data with RSA public key on token/current user store certificate.
- Decrypt, decrypts cipher using RSA private key on token/current user store.
- Sign Data, signs raw data with private key (RSA or ECDSA).
- Sign Hash, signs a pre-computed hash with private key (RSA or ECDSA).
- Verify Data, verifies signature over raw data using certificate public key.
- Verify Hash, verifies signature over pre-computed hash using certificate public key.

#### PKCS#7 Features

- CMS Encrypt, using certificates (RSA/OAEP or PKCS#1) with optional symmetric algorithm.
- CMS Decrypt, using private key to decrypt data.
- CMS Sign, using private key (optionally detached signature) to sign data.
- CMS Verify, verifies signature using public key and optional original data (if detached).

#### PKCS#10 Features

- Generate CSR, generates PKCS#10 CSR (Certificate Signing Request) using requested key algorithm/size, returning DER or PEM.
- Import, imports a certificate to token/current user store, associating it with existing key pair.
- Export, exports a certificate (DER) from token/current user store by thumbprint.

## Documentation and Sample

X509Store.Service is fully documented with the inline XML documentation that is displayed by the most of the modern IDEs during the application development.

You can find sample code of using features in the following:
* [X509Store.Service sample](src/Vira.X509Store.Sample)

## License

X509Store.Service is available under the terms of the [GNU Affero General Public License, Version 3.0](https://www.gnu.org/licenses/agpl-3.0).  
[Human friendly license summary](https://www.gnu.org/licenses/agpl-3.0-standalone.html) is available at tldrlegal.com but the [full license text](LICENSE.txt) always prevails.

## Support

Have you found a bug, want to suggest a new feature, or just need help?  
Don't hesitate to open an issue in our public [issue tracker](https://github.com/vira-systems/X509Store/issues).

## About

X509Store.Service has been written by Vira Systems.  
Please visit our website - [vira.systems](https://www.vira.systems) - for more information.
