'use strict';
import { Convert, Dastyar, KeyInfo, SubjectAltNames, CertificateRequest } from './dastyar.js';

window.addEventListener('load', (e) => {

    let setSelectedCertificate = (element, thumbprint, store) => {
        thumbprint ??= '';
        element.value = thumbprint;
        document.querySelector('.select-store-certificate-result').value = '';
        document.querySelector('.select-token-certificate-result').value = '';
        document.querySelector('.select-token-certificate-instore-result').value = '';
        document.getElementById('enc-cert').value = thumbprint;
        document.getElementById('dec-cert').value = thumbprint;
        document.getElementById('sign-data-cert').value = thumbprint;
        document.getElementById('vrfy-data-cert').value = thumbprint;
        document.getElementById('sign-hash-cert').value = thumbprint;
        document.getElementById('vrfy-hash-cert').value = thumbprint;
        document.getElementById('cms-enc-cert').value = thumbprint;
        document.getElementById('cms-dec-cert').value = thumbprint;
        document.getElementById('cms-sign-cert').value = thumbprint;
        document.getElementById('cms-vrfy-cert').value = thumbprint;
        document.getElementById('export-cert').value = thumbprint;
        document.getElementById('enc-store').value = store;
        document.getElementById('dec-store').value = store;
        document.getElementById('sign-data-store').value = store;
        document.getElementById('vrfy-data-store').value = store;
        document.getElementById('sign-hash-store').value = store;
        document.getElementById('vrfy-hash-store').value = store;
        document.getElementById('cms-enc-store').value = store;
        document.getElementById('cms-dec-store').value = store;
        document.getElementById('cms-sign-store').value = store;
        document.getElementById('cms-vrfy-store').value = store;
        document.getElementById('export-store').value = store;
    }
    let createCertificateRequest = (signatureAlg, subjectDn, pem) => {
        let keySize = parseInt(document.getElementById('key-size').value, 10);
        let ellipticCurve = parseInt(document.getElementById('elliptic-curve').value, 10);
        const dns = document.getElementById('dns').value;
        const ip = document.getElementById('ip').value;
        const rfc822 = document.getElementById('rfc822').value;
        const upn = document.getElementById('upn').value;
        const uri = document.getElementById('uri').value;
        if (signatureAlg > 0 && signatureAlg < 5) {
            keySize = keySize | 2048;
            ellipticCurve = null;
        } else if (signatureAlg > 4 && signatureAlg < 10) {
            keySize = null;
            ellipticCurve = ellipticCurve | Dastyar.EllipticCurve.brainpoolP256r1;
        }
        const subjectAltNames = dns || ip || rfc822 || upn || uri
            ? new SubjectAltNames(dns, ip, rfc822, upn, uri)
            : null;
        return new CertificateRequest(
            subjectDn,
            subjectAltNames,
            pem,
            new KeyInfo(signatureAlg, keySize, ellipticCurve),
        )
    }

    const status = document.querySelector('.status');
    Dastyar.init((state) => {
        switch (state) {
            case Dastyar.State.Initializing:
                status.innerHTML = 'Status: Initializing...';
                break;
            case Dastyar.State.Connecting:
                status.innerHTML = 'Status: Connecting to the service...';
                break;
            case Dastyar.State.Completed:
                status.innerHTML = 'Status: Connection established successfully.';
                break;
            default:
        }
    });

    document.querySelector('.get-token-info').addEventListener('click', (e) => {
        Dastyar.getTokenInfo((result) => {
            if (result.succeeded) {
                document.querySelector('.get-token-info-result').value = JSON.stringify(result.data);
            } else {
                document.querySelector('.get-token-info-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
            }
        });
    });

    document.querySelector('.get-mechanism-infos').addEventListener('click', (e) => {
        Dastyar.getMechanismInfos((result) => {
            if (result.succeeded) {
                document.querySelector('.get-mechanism-infos-result').value = JSON.stringify(result.data);
            } else {
                document.querySelector('.get-mechanism-infos-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
            }
        });
    });

    document.querySelector('.select-store-certificate').addEventListener('click', (e) => {
        const findType = document.getElementById('store-option').value;
        const findValue = document.getElementById('store-value').value;
        Dastyar.storeCertificates(findType, findValue, (result) => {
            if (result.succeeded) {
                setSelectedCertificate(document.querySelector('.select-store-certificate-result'), result.data.thumbprint, '1');
            } else {
                document.querySelector('.select-store-certificate-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
            }
        });
    });

    document.querySelector('.select-token-certificate').addEventListener('click', (e) => {
        const findType = document.getElementById('token-option').value;
        const findValue = document.getElementById('token-value').value;
        Dastyar.tokenCertificates(findType, findValue, (result) => {
            if (result.succeeded) {
                setSelectedCertificate(document.querySelector('.select-token-certificate-result'), result.data.thumbprint, '0');
            } else {
                document.querySelector('.select-token-certificate-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
            }
        });
    });

    document.querySelector('.select-token-certificate-instore').addEventListener('click', (e) => {
        const findType = document.getElementById('instore-option').value;
        const findValue = document.getElementById('instore-value').value;
        Dastyar.tokenCertificatesFromStore(findType, findValue, (result) => {
            if (result.succeeded) {
                setSelectedCertificate(document.querySelector('.select-token-certificate-instore-result'), result.data.thumbprint, '0');
            } else {
                document.querySelector('.select-token-certificate-instore-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
            }
        });
    });

    document.querySelector('.encrypt').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('enc-cert').value;
        const alg = document.getElementById('enc-alg').value;
        const mode = document.getElementById('enc-mode').value;
        const data = document.getElementById('enc-data').value;
        const store = document.getElementById('enc-store').value;
        if (store === '0') {
            Dastyar.encryptByToken(thumbprint, data, alg, mode, (result) => {
                if (result.succeeded) {
                    document.querySelector('.encryption-result').value = result.data;
                    document.getElementById('dec-data').value = result.data;
                } else {
                    document.querySelector('.encryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.encryptByStore(thumbprint, data, alg, mode, (result) => {
                if (result.succeeded) {
                    document.querySelector('.encryption-result').value = result.data;
                    document.getElementById('dec-data').value = result.data;
                } else {
                    document.querySelector('.encryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.decrypt').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('dec-cert').value;
        const alg = document.getElementById('dec-alg').value;
        const mode = document.getElementById('dec-mode').value;
        const cipher = document.getElementById('dec-data').value;
        const store = document.getElementById('dec-store').value;
        if (store === '0') {
            Dastyar.decryptByToken(thumbprint, cipher, alg, mode, (result) => {
                if (result.succeeded) {
                    const plain = Convert.base64ToUtf8(result.data);
                    document.querySelector('.decryption-result').value = plain;
                } else {
                    document.querySelector('.decryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.decryptByStore(thumbprint, cipher, alg, mode, (result) => {
                if (result.succeeded) {
                    const plain = Convert.base64ToUtf8(result.data);
                    document.querySelector('.decryption-result').value = plain;
                } else {
                    document.querySelector('.decryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.getElementById('sign-data-data').addEventListener('change', (e) => {
        document.getElementById('vrfy-data-org').value = e.target.value;
    });
    document.querySelector('.sign-data').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('sign-data-cert').value;
        const data = document.getElementById('sign-data-data').value;
        const alg = document.getElementById('sign-data-alg').value;
        const mode = document.getElementById('sign-data-mode').value;
        const format = document.getElementById('sign-data-format').value;
        const store = document.getElementById('sign-data-store').value;
        if (store === '0') {
            Dastyar.signDataByToken(thumbprint, data, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.sign-data-result').value = result.data;
                    document.getElementById('vrfy-data-sig').value = result.data;
                } else {
                    document.getElementById('sign-data-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.signDataByStore(thumbprint, data, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.sign-data-result').value = result.data;
                    document.getElementById('vrfy-data-sig').value = result.data;
                } else {
                    document.getElementById('sign-data-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.vrfy-data').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('vrfy-data-cert').value;
        const data = document.getElementById('vrfy-data-org').value;
        const signatute = document.getElementById('vrfy-data-sig').value;
        const alg = document.getElementById('vrfy-data-alg').value;
        const mode = document.getElementById('vrfy-data-mode').value;
        const format = document.getElementById('vrfy-data-format').value;
        const store = document.getElementById('vrfy-data-store').value;
        if (store === '0') {
            Dastyar.verifyDataByToken(thumbprint, data, signatute, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.vrfy-data-result').value = result.data;
                } else {
                    document.querySelector('.vrfy-data-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.verifyDataByStore(thumbprint, data, signatute, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.vrfy-data-result').value = result.data;
                } else {
                    document.querySelector('.vrfy-data-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.sign-hash').addEventListener('click', (e) => {
        debugger;
        const thumbprint = document.getElementById('sign-hash-cert').value;
        const hash = document.getElementById('sign-hash-data').value;
        const alg = document.getElementById('sign-hash-alg').value;
        const mode = document.getElementById('sign-hash-mode').value;
        const format = document.getElementById('sign-hash-format').value;
        const store = document.getElementById('sign-hash-store').value;
        if (store === '0') {
            Dastyar.signHashByToken(thumbprint, hash, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.sign-data-result').value = result.data;
                    document.getElementById('vrfy-data-data').value = result.data;
                } else {
                    document.querySelector('.sign-data-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.signHashByStore(thumbprint, hash, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.sign-data-result').value = result.data;
                    document.getElementById('vrfy-data-data').value = result.data;
                } else {
                    document.querySelector('.sign-data-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.vrfy-hash').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('vrfy-hash-cert').value;
        const hash = document.getElementById('vrfy-hash-org').value;
        const signature = document.getElementById('vrfy-hash-sig').value;
        const alg = document.getElementById('vrfy-hash-alg').value;
        const mode = document.getElementById('vrfy-hash-mode').value;
        const format = document.getElementById('vrfy-hash-format').value;
        const store = document.getElementById('vrfy-hash-store').value;
        if (store === '0') {
            Dastyar.verifyHashByToken(thumbprint, hash, signature, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.vrfy-hash-result').value = result.data;
                } else {
                    document.querySelector('.vrfy-hash-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.verifyHashByStore(thumbprint, hash, signature, alg, mode, format, (result) => {
                if (result.succeeded) {
                    document.querySelector('.vrfy-hash-result').value = result.data;
                } else {
                    document.querySelector('.vrfy-hash-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.cms-encrypt').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('cms-enc-cert').value;
        const data = document.getElementById('cms-enc-data').value;
        const hashAlg = document.getElementById('cms-hash-alg').value;
        const mode = document.getElementById('cms-enc-mode').value;
        const encAlg = document.getElementById('cms-enc-alg').value;
        const store = document.getElementById('cms-enc-store').value;
        if (store === '0') {
            Dastyar.cmsEncryptByToken([thumbprint], data, hashAlg, mode, encAlg, (result) => {
                if (result.succeeded) {
                    document.querySelector('.cms-encryption-result').value = result.data;
                    document.getElementById('cms-dec-data').value = result.data;
                } else {
                    document.querySelector('.cms-encryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.cmsEncryptByStore([thumbprint], data, hashAlg, mode, encAlg, (result) => {
                if (result.succeeded) {
                    document.querySelector('.cms-encryption-result').value = result.data;
                    document.getElementById('cms-dec-data').value = result.data;
                } else {
                    document.querySelector('.cms-encryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.cms-decrypt').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('cms-dec-cert').value;
        const cipher = document.getElementById('cms-dec-data').value;
        const store = document.getElementById('cms-dec-store').value;
        if (store === '0') {
            Dastyar.cmsDecryptByToken(thumbprint, cipher, (result) => {
                if (result.succeeded) {
                    const plain = Convert.base64ToUtf8(result.data);
                    document.querySelector('.cms-decryption-result').value = plain;
                } else {
                    document.querySelector('.cms-decryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.cmsDecryptByStore(thumbprint, cipher, (result) => {
                if (result.succeeded) {
                    const plain = Convert.base64ToUtf8(result.data);
                    document.querySelector('.cms-decryption-result').value = plain;
                } else {
                    document.querySelector('.cms-decryption-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.cms-sign').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('cms-sign-cert').value;
        const data = document.getElementById('cms-sign-data').value;
        const detached = document.getElementById('cms-sign-detached').checked;
        const store = document.getElementById('cms-sign-store').value;
        if (store === '0') {
            Dastyar.cmsSignByToken(thumbprint, data, detached, (result) => {
                if (result.succeeded) {
                    document.querySelector('.cms-signing-result').value = result.data;
                    document.getElementById('cms-signed-data').value = result.data;
                } else {
                    document.querySelector('.cms-signing-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.cmsSignByStore(thumbprint, data, detached, (result) => {
                if (result.succeeded) {
                    document.querySelector('.cms-signing-result').value = result.data;
                    document.getElementById('cms-signed-data').value = result.data;
                } else {
                    document.querySelector('.cms-signing-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.querySelector('.cms-verify').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('cms-vrfy-cert').value;
        const signedData = document.getElementById('cms-signed-data').value;
        const originalData = document.getElementById('cms-original-data').value;
        const validateCert = document.getElementById('cms-validate-cert').checked;
        const store = document.getElementById('cms-vrfy-store').value;
        if (store === '0') {
            Dastyar.cmsVerifyByToken(thumbprint, signedData, originalData, validateCert, (result) => {
                if (result.succeeded) {
                    const certificates = JSON.stringify(result.data.certificates);
                    const plain = result.data.originalData ? Convert.base64ToUtf8(result.data.originalData) : null;
                    document.querySelector('.cms-verifying-result').value = `Verified: ${result.data.verified}\nOriginal data: ${plain}\nCertificates: ${certificates}`;
                } else {
                    document.querySelector('.cms-verifying-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.cmsVerifyByStore(thumbprint, signedData, originalData, validateCert, (result) => {
                if (result.succeeded) {
                    const certificates = JSON.stringify(result.data.certificates);
                    const plain = result.data.originalData ? Convert.base64ToUtf8(result.data.originalData) : null;
                    document.querySelector('.cms-verifying-result').value = `Verified: ${result.data.verified}\nOriginal data: ${plain}\nCertificates: ${certificates}`;
                } else {
                    document.querySelector('.cms-verifying-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });

    document.getElementById('signature-alg').addEventListener('change', (e) => {
        const signatureAlg = parseInt(e.target.value, 10);
        if (signatureAlg > 0 && signatureAlg < 5) {
            document.getElementById('key-size').value = 2048;
            document.getElementById('elliptic-curve').value = '';
        } else if (signatureAlg > 4 && signatureAlg < 10) {
            document.getElementById('key-size').value = '';
            document.getElementById('elliptic-curve').value = Dastyar.EllipticCurve.brainpoolP256r1;
        } else {
            document.getElementById('key-size').value = '';
            document.getElementById('elliptic-curve').value = '';
        }
    });
    let pkcs10CsrResult;
    document.querySelectorAll('.csr-gen-der,.csr-gen-pem').forEach((button) => {
        button.addEventListener('click', (e) => {
            const signatureAlg = parseInt(document.getElementById('signature-alg').value, 10);
            if (signatureAlg < 1 || signatureAlg > 9) {
                alert("The 'Signature Algorithm' is required.");
                return;
            }
            const subjectDn = document.getElementById('subject-dn').value;
            if (!subjectDn) {
                alert("The 'Subject Distinguished Name' is required.");
                return;
            }
            const request = createCertificateRequest(signatureAlg, subjectDn, e.currentTarget.classList.contains('csr-gen-pem'));
            Dastyar.generateCSR(request, (result) => {
                if (result.succeeded) {
                    pkcs10CsrResult = result.data;
                    const csrResult = `CKA Id: ${result.data.ckaId}\nLabel: ${result.data.label}\nPKCS#10 CSR: ${result.data.pkcs10CSR}`;
                    document.querySelector('.csr-result').value = csrResult;
                    document.getElementById('import-ckaId').value = result.data.ckaId;
                    document.getElementById('import-label').value = result.data.label;
                    document.querySelector('.csr-export').disabled = false;
                } else {
                    pkcs10CsrResult = undefined;
                    document.querySelector('.csr-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                    document.querySelector('.csr-export').disabled = true;
                }
            });
        });
    });

    document.querySelector('.csr-export').addEventListener('click', (e) => {
        e.preventDefault();
        if (!pkcs10CsrResult) {
            return;
        }
        const isPEM = pkcs10CsrResult.pkcs10CSR.startsWith('-----');
        const blob = isPEM
            ? new Blob([pkcs10CsrResult.pkcs10CSR], { type: 'text/plain' /*text/plain;charset=utf-8*/ })
            : Convert.base64ToBlob(pkcs10CsrResult.pkcs10CSR);
        Dastyar.saveBlob(blob, `${pkcs10CsrResult.label}-${(isPEM ? 'pem' : 'der')}.p10`);
    });

    document.querySelector('.import-cert').addEventListener('click', (e) => {
        const ckaId = document.getElementById('import-ckaId').value;
        const label = document.getElementById('import-label').value;
        const certificate = document.getElementById('import-certificate').value;
        Dastyar.importToToken(ckaId, label, certificate, (result) => {
            if (result.succeeded) {
                document.querySelector('.import-result').value = result.data;
            } else {
                document.querySelector('.import-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
            }
        });
    });

    document.querySelector('.export-cert').addEventListener('click', (e) => {
        const thumbprint = document.getElementById('export-cert').value;
        const store = document.getElementById('export-store').value;
        if (store === '0') {
            Dastyar.exportFromToken(thumbprint, (result) => {
                if (result.succeeded) {
                    document.querySelector('.export-result').value = result.data;
                } else {
                    document.querySelector('.export-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        } else {
            Dastyar.exportFromStore(thumbprint, (result) => {
                if (result.succeeded) {
                    document.querySelector('.export-result').value = result.data;
                } else {
                    document.querySelector('.export-result').value = `Code: ${result.error.code}\nMessage: ${result.error.message}`;
                }
            });
        }
    });
});
