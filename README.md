Vira X509Store
=======================
**A service for web users to communicate with smart cards, usb hard-tokens and other types of cryptographic hardware.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/vira-systems/Vira.X509Store/tree/master/LICENSE.md)

## Overview

The everyday need of web users to perform digital signatures and other cryptographic operations using X.509 certificates led to the creation of a service that would interface with smart cards and other types of cryptographic hardware on different platforms and provide cryptographic capabilities to developers, while also meeting the needs of web users for signing and other cryptographic operations using their hard-tokens.

For this purpose, several open source projects were used, including [Bouncy Castle](https://www.bouncycastle.org/) (nuget package), which supports cryptography and cryptographic protocols, and [Pkcs11Interop.X509Store](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store) (source code with some modification), which simplifies the integration of PKCS#11 into .NET applications.

I would like to express my special thanks to the contributors of both projects. Especially to [Jaroslav Imrich](https://github.com/jariq), whose various projects helped me to better and deeper understand the PKCS#11 standard.

## Documentation

X509Store.Service is fully documented with the inline XML documentation that is displayed by the most of the modern IDEs during the application development.

The following topics are covered by standalone documents:
* [X509Store.Service web sample](doc/01_CODE_SAMPLES.md)

## License

X509Store.Service is available under the terms of the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).  
[Human friendly license summary](https://www.tldrlegal.com/license/apache-license-2-0-apache-2-0) is available at tldrlegal.com but the [full license text](LICENSE.txt) always prevails.

## Support

Have you found a bug, want to suggest a new feature, or just need help?  
Don't hesitate to open an issue in our public [issue tracker](https://github.com/vira-systems/X509Store.Service/issues).

## About

X509Store.Service has been written by Vira Systems.  
Please visit project website - [vira.systems](https://www.vira.systems/x509store) - for more information.
