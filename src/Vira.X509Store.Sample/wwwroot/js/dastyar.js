/*
 *  Copyright 2025 The Vira.X509Store Project
 *
 *  Licensed under the GNU Affero General Public License, Version 3.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.gnu.org/licenses/agpl-3.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Vira.X509Store project by:
 *  Vira Systems <info@vira.systems>
 */

/* eslint-disable no-undef */
'use strict';
import '../lib/microsoft/signalr/dist/browser/signalr.min.js';

let Utf = (bit = 16) => {
    // Which method are we using 16bit or 8bit (default) ?
    const utf8 = !(bit === 16);
    const escaping = new RegExp('%([0-9A-F]{2})', 'g'); // eg: '&' > %26 > 0x26
    const toSolidBytes = (_, p1) => String.fromCharCode(`0x${p1}`);

    let _btoaUTF16 = (str) => {
        const utf16Code = new Uint16Array(str.length);
        utf16Code.forEach((el, idx, arr) => {
            arr[idx] = str.charCodeAt(idx);
        });
        return btoa(String.fromCharCode(...new Uint8Array(utf16Code.buffer)));
    }

    let _atobUTF16 = (b64) => {
        const str = atob(b64);
        const utf8Code = new Uint8Array(str.length);

        utf8Code.forEach((_, idx, arr) => {
            arr[idx] = str.charCodeAt(idx);
        });

        return String.fromCharCode(...new Uint16Array(utf8Code.buffer));
    }

    let _btoaUTF8 = (str) => {
        return btoa(encodeURIComponent(str).replace(escaping, toSolidBytes));
    }

    let _atobUTF8 = (b64) => {
        return decodeURIComponent(
            atob(b64)
                .split('')
                .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );
    }

    return {
        fromBase64: (str) => {
            return utf8 ? _atobUTF8(str) : _atobUTF16(str)
        },
        toBase64: (str) => {
            return utf8 ? _btoaUTF8(str) : _btoaUTF16(str)
        },
    }
}

export let Convert = window.Convert = (() => {
    return {
        arrayToBase64: (bytes) => {
            const binaryString = String.fromCharCode.apply(null, bytes);
            return btoa(binaryString);
        },
        bufferToBase64: (buffer) => {
            const bytes = new Uint8Array(buffer);
            return Convert.arrayToBase64(bytes);
        },
        base64ToArray: (base64) => {
            const bStr = atob(base64);
            const len = bStr.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        },
        base64ToBuffer: (base64) => {
            return Convert.base64ToArray(base64).buffer;
        },
        base64ToBlob: (base64, mimeType = 'application/octet-stream') => {
            const binary = atob(base64);
            const array = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                array[i] = binary.charCodeAt(i);
            }
            return new Blob([array], { type: mimeType });
        },
        blobToBase64: async (blob) => {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onloadend = () => {
                    resolve(reader.result.split(',')[1]); // Extract Base64 part
                }
                reader.onerror = reject;
                reader.readAsDataURL(blob);
            });
        },
        blobToDataURL: async (blob) => {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onloadend = () => {
                    resolve(reader.result);
                }
                reader.onerror = reject;
                reader.readAsDataURL(blob);
            });
        },
        base64ToUnicode: (str) => {
            return Utf(16).fromBase64(str);
        },
        unicodeToBase64: (str) => {
            return Utf(16).toBase64(str);
        },
        base64ToUtf8: (str) => {
            return Utf(8).fromBase64(str);
        },
        utf8ToBase64: (str) => {
            return Utf(8).toBase64(str);
        },
        bytesToHex: (arr) => {
            return Array.from(arr)
                .map(byte => byte.toString(16).padStart(2, '0'))
                .join('');
            //let hex = '';
            //for (let i = 0; i < arr.length; i++) {
            //    let str = arr[i].toString(16);
            //    let z = 8 - str.length + 1;
            //    str = Array(z).join('0') + str;
            //    hex += str;
            //}
            //return hex;
        },
        hexToBytes: (hex) => {
            if (hex.length % 2 !== 0) {
                throw new Error('Hex string must have an even number of characters.');
            }
            const bytes = [];
            for (let i = 0; i < hex.length; i += 2) {
                const byte = parseInt(hex.substring(i, i + 2), 16);
                bytes.push(byte);
            }
            return bytes;
            //var arr = [];
            //while (hex.length >= 8) {
            //    arr.push(parseInt(hex.substring(0, 8), 16));
            //    hex = hex.substring(8, hex.length);
            //}
            //return arr;
        },
        isBase64: (str) => {
            if (typeof str !== 'string' || str.length === 0) {
                return false;
            }
            const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
            return base64Regex.test(str);
        },
        base64ToObject: (b64) => {
            if (!Convert.isBase64(obj))
                return null;
            const json = Convert.base64ToUnicode(b64);
            return JSON.parse(json);
        },
        objectToBase64: (obj) => {
            if (obj === null || obj === '' || Convert.isBase64(obj))
                return obj;
            if (Array.isArray(obj))
                return Convert.arrayToBase64(obj);
            if (typeof obj === 'string')
                return Convert.unicodeToBase64(obj);
            const json = JSON.stringify(obj);//.replace(/\\/g, "").trim('"');
            return Convert.unicodeToBase64(json);
        },
        toNullableNumber: (val) => {
            if (typeof val === 'number') {
                return val;
            }
            if (typeof val === 'string') {
                try {
                    return parseInt(val, 10);
                } catch {
                    return null;
                }
            }
            return null;
        },
        toNullableString: (val) => {
            if (typeof val === 'string') {
                return val;
            }
            return null;
        },
    }
})();

class KeyInfo {
    constructor(
        signatureAlgorithm = Dastyar.SignatureAlgorithm.SHA256WithRSA,
        keySize = 2048,
        ellipticCurve = Dastyar.EllipticCurve.ANY_EC_CURVE) {
        //keyUsages = null,
        //keyUsageCritical = false,
        //enhancedKeyUsages = null,
        //enhancedKeyUsageCritical = false,
        //authorityKeyIdentifierCritical = false,
        //basicConstraintsCritical = false,
        //certificatePoliciesCritical = false,
        //crlDistributionPointCritical = false,
        //issuerAlternativeNameCritical = false,
        //subjectAlternativeNameCritical = false,
        //subjectKeyIdentifierCritical = false) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.keySize = keySize;
        this.ellipticCurve = ellipticCurve;
        //this.keyUsages = keyUsages;
        //this.keyUsageCritical = keyUsageCritical;
        //this.enhancedKeyUsages = enhancedKeyUsages;
        //this.enhancedKeyUsageCritical = enhancedKeyUsageCritical;
        //this.authorityKeyIdentifierCritical = authorityKeyIdentifierCritical;
        //this.basicConstraintsCritical = basicConstraintsCritical;
        //this.certificatePoliciesCritical = certificatePoliciesCritical;
        //this.crlDistributionPointCritical = crlDistributionPointCritical;
        //this.issuerAlternativeNameCritical = issuerAlternativeNameCritical;
        //this.subjectAlternativeNameCritical = subjectAlternativeNameCritical;
        //this.subjectKeyIdentifierCritical = subjectKeyIdentifierCritical;
    }
}

class SubjectAltNames {
    constructor(dns = '', ip = '', rfc822 = '', upn = '', uri = '') {
        this.dns = dns;
        this.ip = ip;
        this.rfc822 = rfc822;
        this.upn = upn;
        this.uri = uri;
    }
}

class CertificateRequest {
    constructor(subjectDn = '', subjectAltNames = null, pem = false, keyInfo = null, csp = ''/*, crlUrls = [], ocspUrls = [], policyUrls = []*/) {
        this.subjectDn = subjectDn;
        this.subjectAltNames = subjectAltNames;
        this.pem = pem;
        this.keyInfo = keyInfo ?? new KeyInfo();
        this.csp = csp;
        //this.crlUrls = crlUrls;
        //this.ocspUrls = ocspUrls;
        //this.policyUrls = policyUrls;
    }
}

export { KeyInfo, SubjectAltNames, CertificateRequest }

export let Dastyar = window.Dastyar = (() => {
    const digestType = Object.freeze({
        array: 0,
        base64: 1,
        blob: 2,
    });

    const ellipticCurve = Object.freeze({
        ANY_EC_CURVE: 0,
        brainpoolP160r1: 1,
        brainpoolP160t1: 2,
        brainpoolP192r1: 3,
        brainpoolP192t1: 4,
        brainpoolP224r1: 5,
        brainpoolP224t1: 6,
        brainpoolP256r1: 7,
        brainpoolP256t1: 8,
        brainpoolP320r1: 9,
        brainpoolP320t1: 10,
        brainpoolP384r1: 11,
        brainpoolP384t1: 12,
        brainpoolP512r1: 13,
        brainpoolP512t1: 14,
        nistP256: 256,
        nistP384: 384,
        nistP521: 521,
    });

    const encryptionAlgorithm = Object.freeze({
        RC2: 0,
        RC4: 1,
        TripleDES: 2,
        DES: 3,
        AES128: 4,
        AES192: 5,
        AES256: 6,
    });

    const encryptionPaddingMode = Object.freeze({
        PKCS1: 0,
        OAEP: 1,
    });

    const findType = Object.freeze({
        Thumbprint: 0,
        SubjectName: 1,
        SubjectDistinguishedName: 2,
        IssuerName: 3,
        IssuerDistinguishedName: 4,
        SerialNumber: 5,
        TimeValid: 6,
        TimeNotYetValid: 7,
        TimeExpired: 8,
        TemplateName: 9,
        ApplicationPolicy: 10,
        CertificatePolicy: 11,
        Extension: 12,
        KeyUsage: 13,
        SubjectKeyIdentifier: 14,
    });

    const hashAlgorithm = Object.freeze({
        MD5: 0,
        SHA1: 1,
        //SHA224: 2,
        SHA256: 3,
        SHA384: 4,
        SHA512: 5,
        SHA3_256: 6,
        SHA3_384: 7,
        SHA3_512: 8,
    });

    const signatureAlgorithm = Object.freeze({
        SHA1WithRSA: 1,
        SHA256WithRSA: 2,
        SHA384WithRSA: 3,
        SHA512WithRSA: 4,
        SHA1WithECDSA: 5,
        //SHA224WithECDSA: 6,
        SHA256WithECDSA: 7,
        SHA384WithECDSA: 8,
        SHA512WithECDSA: 9,
    });

    const signatureFormat = Object.freeze({
        IeeeP1363FixedFieldConcatenation: 0,
        Rfc3279DerSequence: 1,
    });

    const signaturePaddingMode = Object.freeze({
        PKCS1: 0,
        PSS: 1,
    });

    const x509EnhancedKeyUsage = Object.freeze({
        None: 0,
        AnyExtendedKeyUsage: 1,
        ServerAuthentication: 2,
        ClientAuthentication: 4,
        CodeSigning: 8,
        EmailProtection: 16,
        TimeStamping: 32,
        SmartCardLogon: 64,
        OcspSigning: 128,
        MacAddress: 256,
        EFS: 512,
        EFSRecovery: 1024,
        SCVPServer: 2048,
        SCVPClient: 4096,
        IPsecIKE: 8192,
        IPsecIKEIntermediate: 16384,
        KeyRecovery: 32768,
        DocumentSigning: 65536,
        IntelAMTManagement: 131072,
        TSLSigning: 262144,
        AdobeAuthenticDocumentTrust: 524288,
    });

    const x509KeyUsage = Object.freeze({
        None: 0,
        EncipherOnly: 1,
        CrlSign: 2,
        KeyCertSign: 4,
        KeyAgreement: 8,
        DataEncipherment: 16,
        KeyEncipherment: 32,
        NonRepudiation: 64,
        DigitalSignature: 128,
        DecipherOnly: 32768
    });

    const State = Object.freeze({
        Initializing: 0,
        Connecting: 1,
        Completed: 2,
    });

    let _connection,
        _callbacks = [],
        _spinnerHtml = `
<style>
    .v-spinner-container {
      border: none;
      border-radius: 8px;
      box-shadow: 0 5px 30px rgba(0, 0, 0, 0.25);
      position: fixed;
      top: 50%;
      left: 50%;
      margin-top: -50px;
      margin-left: -50px;
      width: 84px;
      height: 84px;
    }
    .v-spinner-container::backdrop {
      background-color: rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(4px);
      transition: opacity 0.5s ease-in-out;
      opacity: 1;
    }
    .v-spinner {
      width: 50px;
      aspect-ratio: 1;
      display: grid;
      border: 4px solid #0000;
      border-radius: 50%;
      border-color: #ccc #0000;
      animation: l16 1s infinite linear;
    }
    .v-spinner::before,
    .v-spinner::after {
      content: "";
      grid-area: 1/1;
      margin: 2px;
      border: inherit;
      border-radius: 50%;
    }
    .v-spinner::before {
      border-color: #f03355 #0000;
      animation: inherit;
      animation-duration: .5s;
      animation-direction: reverse;
    }
    .v-spinner::after {
      margin: 8px;
    }
    @keyframes l16 {
      100%{transform: rotate(1turn)}
    }
</style>
<dialog class="v-spinner-container">
  <div class="v-spinner"></div>
</dialog>
        `,
        _spinnerStatus = 'closed';
    let _isWindowsPlatform = () => {
        const nav = window.navigator || {};
        const platform = (nav.userAgentData && nav.userAgentData.platform) || nav.platform || nav.userAgent || '';
        return /\b(Win(dows)?|Windows NT|Win32|Win64|WOW64|WinCE)\b/i.test(platform);
    }
    let _registerCallback = (callback, name) => {
        if (typeof callback === 'function' && _callbacks.findIndex(e => e.name === name) === -1) {
            _callbacks.push({ name: name, value: callback });
        }
    }
    let _unregisterCallback = (name) => {
        let index = _callbacks.findIndex(e => e.name === name);
        if (index !== -1) {
            _callbacks.splice(index, index);
        }
    }
    let _startConnection = async (callback) => {
        try {
            _showSpinner();
            await _connection.start();
            console.log('SignalR Connected.');
            if (typeof callback === 'function') {
                callback(State.Completed);
            }
            _hideSpinner();
        } catch (err) {
            _hideSpinner();
            console.log(err);
            setTimeout(_startConnection, 5000);
        }
    }
    let _showSpinner = () => {
        if (_spinnerStatus !== 'closed') return;
        let spinner = document.querySelector('.v-spinner-container');
        if (!spinner) {
            document.body.insertAdjacentHTML('beforeend', _spinnerHtml);
            spinner = document.querySelector('.v-spinner-container');
        }
        spinner.showModal();
        _spinnerStatus = 'modal';
        //    document.body.insertAdjacentHTML('beforeend', _spinnerHtml);
        //    document.querySelector('.v-spinner-container').showModal();
    }
    let _hideSpinner = () => {
        //const spinner = document.querySelector('.v-spinner-container');
        //spinner.close();
        //spinner.remove();
        document.querySelector('.v-spinner-container').close();
        _spinnerStatus = 'closed';
    }
    let _showPinDialog = (message) => {
        // eslint-disable-next-line no-unused-vars
        return new Promise((resolve, reject) => {
            let dialogHtml = `
<style>
    #pin-dialog {
        border: 2px solid darkred;
        border-collapse: collapse;
        font-size: 0.8em;
        font-family: math;
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
        border-radius: 5px;
        overflow: hidden; /* Ensures box-shadow and border-radius work together */
    }
    #pin-dialog img {
        display:inline-flex;
        margin:-.5rem;
    }
    #pin-dialog span {
        display:inline-block;
        color:darkred;
        font-size:smaller;
        font-weight:700;
        position:absolute;
        left:4.5rem;
        top:2.95;
    }
    #pin-dialog p {
        margin-top:1rem;
    }
    #pin-dialog input {
        margin: 0 4px;
    }
    #pin-dialog div {
        float: inline-end;
    }
    .close {
        border-width: thin;
    }
    .close,
    .confirm {
        background: none;
        border: 1px solid #ccc;
        border-radius: 4px;
        padding: 6px 12px;
        margin: 0 4px;
        font-size: 0.8em;
        font-weight: bold;
        cursor: pointer;
        transition: all 0.3s ease; /* Add transition for hover effect */
        color: darkred;
        border-color: maroon;
    }
    .close:hover,
    .confirm:hover {
        background-color: darkred;
        color: #ffffff;
    }
</style>
<dialog id="pin-dialog">
    <form>
        <img alt="logo" width="64" src="data:image/png;base64,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" />
        <span>Vira Systems</span>
        <p>
            <label>
                ${message}
                <input type="password" id="pin" autofocus required />
            </label>
        </p>
        <div>
            <button class="close">Cancel</button>
            <button class="confirm">Confirm</button>
        </div>
    </form>
</dialog>
`;
            let dialog = document.getElementById('pin-dialog');
            if (dialog) {
                dialog.showModal();
                return;
            }
            document.body.insertAdjacentHTML('beforeend', dialogHtml);

            dialog = document.getElementById('pin-dialog');
            const pin = document.getElementById('pin');
            const close = document.querySelector('.close');
            const confrm = document.querySelector('.confirm');

            pin.addEventListener('keyup', (e) => {
                if (e.key === 'Enter'/* || e.keyCode === 13*/) {
                    e.preventDefault();
                    dialog.close(pin.value);
                }
            });
            close.addEventListener('click', (e) => {
                e.preventDefault();
                dialog.close();
            });
            confrm.addEventListener('click', (e) => {
                e.preventDefault();
                dialog.close(pin.value);
            });
            dialog.addEventListener('close', () => {
                if (dialog.returnValue) {
                    resolve(dialog.returnValue);
                } else {
                    resolve(pin.value);
                }
            });

            dialog.showModal();
        });
    }
    let _showCertDialog = async (certs) => {
        // eslint-disable-next-line no-unused-vars
        return new Promise((resolve, reject) => {
            let dialogHtml = `
<style>
    .dialog {
        border: 2px solid darkred;
        border-collapse: collapse;
        font-size: 0.8em;
        font-family: math;
        min-width: 400px;
        max-width: 70%;
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
        border-radius: 5px;
        overflow: hidden; /* Ensures box-shadow and border-radius work together */
    }
    header h3 {
        color: darkred;
        padding: .5rem .5rem 0;
        text-align: center;
    }
    .content {
        max-height: 400px;
        overflow-y: auto;
        padding: 10px;
    }
        .content button,
        footer button {
            background: none;
            border: 1px solid #ccc;
            border-radius: 4px;
            padding: 6px 12px;
            margin: 0 4px;
            font-size: 0.8em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease; /* Add transition for hover effect */
            color: darkred;
            border-color: maroon;
        }
            .content button:hover,
            footer button:hover {
                background-color: darkred;
                color: #ffffff;
            }
        .content thead {
            position: -webkit-sticky;
            position: sticky;
                top: -10px;
        }
            .content thead tr {
                background-color: darkred;
                color: #ffffff;
                text-align: left;
            }
        .content tbody {
            left: 0;
        }
            .content tbody tr {
                border-bottom: 1px solid #dddddd;
            }
                .content tbody tr:nth-of-type(even) {
                    background-color: #f3f3f3;
                }
                .content tbody tr:hover {
                    background-color: #f1f1f1;
                }
        .content th,
        .content td {
            padding: 4px;
        }
            .content td:last-child {
                text-align: center;
            }
    footer div {
        float: inline-end;
    }
    footer button {
        background-color: darkred;
        color: #ffffff;
        margin: .75rem 0 0;
        min-width: 4rem;
    }
</style>
<dialog id="certDialog" class="dialog">
    <header>
        <h3>Select a Certificate</h3>
    </header>
    <div class="content">
        <form>
            <table id="certTable">
                <colgroup>
                    <col style="width: auto;" />
                    <col style="width: auto;" />
                    <col style="width: auto;" />
                    <col style="width: auto;" />
                    <col style="width: 10.4rem;" />
                    <col style="width: 10.4rem;" />
                    <col style="width: 6.5rem;" />
                    <col />
                </colgroup>
                <thead>
                    <tr>
                        <th>Friendly Name</th>
                        <th>Subject</th>
                        <th>Issuer</th>
                        <th>Serial Number</th>
                        <th>Valid From</th>
                        <th>Valid To</th>
                        <th>Has Private</th>
                        <th>&nbsp;</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Certificates will be populated here -->
                </tbody>
            </table>
        </form>
    </div>
    <footer>
        <div>
            <button id="closeBtn">Close</button>
        </div>
    </footer>
</dialog>
`;
            let dialog = document.getElementById('certDialog');
            if (dialog) {
                dialog.showModal();
                return;
            }
            document.body.insertAdjacentHTML('beforeend', dialogHtml);

            const tbody = document.getElementById('certTable').querySelector('tbody');
            tbody.innerHTML = '';
            // eslint-disable-next-line no-unused-vars
            certs.forEach((cert, idx) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
            <td>${cert.friendlyName}</td>
            <td>${cert.subject}</td>
            <td>${cert.issuer}</td>
            <td>${cert.serialNumber}</td>
            <td>${cert.notBefore ? new Date(cert.notBefore).toUTCString() : ''}</td>
            <td>${cert.notAfter ? new Date(cert.notAfter).toUTCString() : ''}</td>
            <td>${cert.hasPrivateKey ? 'Yes' : 'No'}</td>
            <td><button data-thumbprint="${cert.thumbprint}" data-commonName="${cert.commonName}">Select</button></td>
            `;
                tbody.appendChild(tr);
            });

            let selectedData;
            Array.from(tbody.querySelectorAll('button[data-thumbprint]')).forEach(btn => {
                btn.onclick = (e) => {
                    e.preventDefault();
                    selectedData = {
                        commonName: btn.getAttribute('data-commonName'),
                        thumbprint: btn.getAttribute('data-thumbprint')
                    };
                    dialog.close(JSON.stringify(selectedData));
                };
            });

            const close = document.getElementById('closeBtn');
            close.addEventListener('click', (e) => {
                e.preventDefault();
                dialog.close();
            });

            dialog = document.getElementById('certDialog');
            dialog.addEventListener('close', () => {
                if (dialog.returnValue) {
                    resolve(dialog.returnValue);
                } else {
                    resolve(JSON.stringify(selectedData));
                }
            });

            dialog.showModal();
        });
    }
    let _tokenInfoCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'tokenInfo');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('tokenInfo');
            }
        }
        _hideSpinner();
    }
    let _mechanismInfosCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'mechanismInfos');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('mechanismInfos');
            }
        }
        _hideSpinner();
    }
    let _certificateListCallback = async (result) => {
        const callback = _callbacks.find(e => e.name === result.callback);
        if (callback) {
            try {
                if (result.succeeded) {
                    const selectedData = await _showCertDialog(result.data);
                    callback.value({ succeeded: true, data: JSON.parse(selectedData) });
                } else {
                    callback.value(result);
                }
            } finally {
                _unregisterCallback(result.callback);
            }
        }
        _hideSpinner();
    }
    let _encryptCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'encrypt');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('encrypt');
            }
        }
        _hideSpinner();
    }
    let _decryptCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'decrypt');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('decrypt');
            }
        }
        _hideSpinner();
    }
    let _signCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'sign');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('sign');
            }
        }
        _hideSpinner();
    }
    let _verifyCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'verify');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('verify');
            }
        }
        _hideSpinner();
    }
    let _cmsEncryptCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'cmsEncrypt');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('cmsEncrypt');
            }
        }
        _hideSpinner();
    }
    let _cmsDecryptCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'cmsDecrypt');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('cmsDecrypt');
            }
        }
        _hideSpinner();
    }
    let _cmsSignCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'cmsSign');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('cmsSign');
            }
        }
        _hideSpinner();
    }
    let _cmsVerifyCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'cmsVerify');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('cmsVerify');
            }
        }
        _hideSpinner();
    }
    let _csrCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'csr');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('csr');
            }
        }
        _hideSpinner();
    }
    let _importCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'import');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('import');
            }
        }
        _hideSpinner();
    }
    let _exportCallback = (result) => {
        const callback = _callbacks.find(e => e.name === 'export');
        if (callback) {
            try {
                callback.value(result);
            } finally {
                _unregisterCallback('export');
            }
        }
        _hideSpinner();
    }

    return {
        get ConnectionState() {
            return _connection ? _connection.state : signalR.HubConnectionState.Disconnected;
        },
        get IsConnected() {
            return _connection ? _connection.state === signalR.HubConnectionState.Connected : false;
        },
        get DigestType() {
            return digestType;
        },
        get IsWindowsPlatform() {
            return _isWindowsPlatform();
        },
        get EllipticCurve() {
            return ellipticCurve;
        },
        get EncryptionAlgorithm() {
            return encryptionAlgorithm;
        },
        get EncryptionPaddingMode() {
            return encryptionPaddingMode;
        },
        get FindType() {
            return findType;
        },
        get HashAlgorithm() {
            return hashAlgorithm;
        },
        get SignatureAlgorithm() {
            return signatureAlgorithm;
        },
        get SignatureFormat() {
            return signatureFormat;
        },
        get SignaturePaddingMode() {
            return signaturePaddingMode;
        },
        get X509EnhancedKeyUsage() {
            return x509EnhancedKeyUsage;
        },
        get X509KeyUsage() {
            return x509KeyUsage;
        },
        get State() {
            return State;
        },
        get Version() {
            return '1.0.0';
        },

        init: async (callback) => {
            if (Dastyar.IsConnected) {
                if (typeof callback === 'function') {
                    callback(State.Completed);
                }
                return;
            }
            _showSpinner();
            if (typeof callback === 'function') {
                //Status: Initializing...
                callback(State.Initializing);
            }

            _connection = new signalR.HubConnectionBuilder()
                .configureLogging(signalR.LogLevel.Warning) // Optional: Configure logging
                .withUrl('http://localhost:5342/Store')
                .withAutomaticReconnect()
                .build();

            _connection.on('GetKeyPin', async () => {
                let pin = await _showPinDialog('Enter key pin: ');
                if (pin) {
                    return { cancel: false, pin: pin };
                } else {
                    return { cancel: true };
                }
            });

            _connection.on('GetTokenPin', async () => {
                let pin = await _showPinDialog('Enter token pin: ');
                if (pin) {
                    return { cancel: false, pin: pin };
                } else {
                    return { cancel: true };
                }
            });

            _connection.on('TokenInfo', _tokenInfoCallback);
            _connection.on('MechanismInfos', _mechanismInfosCallback);
            _connection.on('CertificateList', _certificateListCallback);
            _connection.on('Encrypt', _encryptCallback);
            _connection.on('Decrypt', _decryptCallback);
            _connection.on('Sign', _signCallback);
            _connection.on('Verify', _verifyCallback);
            _connection.on('CmsEncrypt', _cmsEncryptCallback);
            _connection.on('CmsDecrypt', _cmsDecryptCallback);
            _connection.on('CmsSign', _cmsSignCallback);
            _connection.on('CmsVerify', _cmsVerifyCallback);
            _connection.on('CSR', _csrCallback);
            _connection.on('Import', _importCallback);
            _connection.on('Export', _exportCallback);

            if (typeof callback === 'function') {
                callback(State.Connecting);
            }

            // Start the connection.
            await _startConnection(callback);
        },
        start: async (callback) => {
            await _startConnection(callback);
        },

        getTokenInfo: async (callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'tokenInfo');
                await _connection.invoke('TokenInfo');
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        getMechanismInfos: async (callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'mechanismInfos');
                await _connection.invoke('MechanismInfos');
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },

        storeCertificates: async (findType, findValue, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'storeCallback');
                await _connection.invoke('StoreCertificates',
                    Convert.toNullableNumber(findType),
                    Convert.toNullableString(findValue),
                    'storeCallback');
            } catch (err) {
                _hideSpinner();
                console.error(err);

            }
        },
        tokenCertificates: async (findType, findValue, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'tokenCallback');
                await _connection.invoke('TokenCertificates',
                    Convert.toNullableNumber(findType),
                    Convert.toNullableString(findValue),
                    'tokenCallback');
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        tokenCertificatesFromStore: async (findType, findValue, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'tokenInStoreCallback');
                await _connection.invoke('TokenCertificatesFromStore',
                    Convert.toNullableNumber(findType),
                    Convert.toNullableString(findValue),
                    'tokenInStoreCallback');
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },

        digest: async (dataToHash = {}, hashAlg = hashAlgorithm.SHA256, resultType = digestType.array) => {
            let alg;
            switch (hashAlg) {
                case hashAlgorithm.SHA1:
                    alg = 'SHA-1';
                    break;
                case hashAlgorithm.SHA256:
                    alg = 'SHA-256';
                    break;
                case hashAlgorithm.SHA384:
                    alg = 'SHA-384';
                    break;
                case hashAlgorithm.SHA512:
                    alg = 'SHA-512';
                    break;
                default:
                    throw new Error('Not supported hash algorithm.');
            }
            const message = JSON.stringify(dataToHash);
            const msgUint8 = new TextEncoder().encode(message);
            const hashBuffer = await window.crypto.subtle.digest(alg, msgUint8);
            switch (resultType) {
                case digestType.array:
                    return Array.from(new Uint8Array(hashBuffer));
                case digestType.base64:
                    return Convert.bufferToBase64(hashBuffer);
                case digestType.blob:
                    return new Blob([Array.from(new Uint8Array(hashBuffer))], { type: 'application/octetstream' });
                default:
                    throw new Error('Not supported digest yype.');
            }
        },
        saveBlob: (blob, fileName) => {
            //Check the Browser type and download the File.
            let isIE = !!document.documentMode || false;
            if (isIE) {
                window.navigator.msSaveBlob(blob, fileName);
            } else {
                let uri = window.URL || window.webkitURL,
                    link = uri.createObjectURL(blob),
                    a = $('<a/>');
                a.attr('download', fileName);
                a.attr('href', link);
                $('body').append(a);
                a[0].click();
                $('body').remove(a);
            }
        },

        encryptByToken: async (thumbprint, data, algorithm, mode, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'encrypt');
                await _connection.invoke('EncryptByToken',
                    thumbprint,
                    Convert.objectToBase64(data),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        encryptByStore: async (thumbprint, data, algorithm, mode, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'encrypt');
                await _connection.invoke('EncryptByStore',
                    thumbprint,
                    Convert.objectToBase64(data),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        decryptByToken: async (thumbprint, cipher, algorithm, mode, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'decrypt');
                await _connection.invoke('DecryptByToken',
                    thumbprint,
                    Convert.objectToBase64(cipher),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        decryptByStore: async (thumbprint, cipher, algorithm, mode, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'decrypt');
                await _connection.invoke('DecryptByStore',
                    thumbprint,
                    Convert.objectToBase64(cipher),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        signDataByToken: async (thumbprint, data, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'sign');
                await _connection.invoke('SignDataByToken',
                    thumbprint,
                    Convert.objectToBase64(data),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        signDataByStore: async (thumbprint, data, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'sign');
                await _connection.invoke('SignDataByStore',
                    thumbprint,
                    Convert.objectToBase64(data),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        signHashByToken: async (thumbprint, hash, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'sign');
                await _connection.invoke('SignHashByToken',
                    thumbprint,
                    Convert.objectToBase64(hash),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        signHashByStore: async (thumbprint, hash, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'sign');
                await _connection.invoke('SignHashByStore',
                    thumbprint,
                    Convert.objectToBase64(hash),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        verifyDataByToken: async (thumbprint, data, signature, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'verify');
                await _connection.invoke('VerifyDataByToken',
                    thumbprint,
                    Convert.objectToBase64(data),
                    Convert.objectToBase64(signature),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        verifyDataByStore: async (thumbprint, data, signature, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'verify');
                await _connection.invoke('VerifyDataByStore',
                    thumbprint,
                    Convert.objectToBase64(data),
                    Convert.objectToBase64(signature),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        verifyHashByToken: async (thumbprint, hash, signature, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'verify');
                await _connection.invoke('VerifyHashByToken',
                    thumbprint,
                    Convert.objectToBase64(hash),
                    Convert.objectToBase64(signature),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        verifyHashByStore: async (thumbprint, hash, signature, algorithm, mode, format, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'verify');
                await _connection.invoke('VerifyHashByStore',
                    thumbprint,
                    Convert.objectToBase64(hash),
                    Convert.objectToBase64(signature),
                    Convert.toNullableNumber(algorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(format));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },

        cmsEncryptByToken: async (thumbprints, data, hashAlgorithm, mode, encAlgorithm, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsEncrypt');
                await _connection.invoke('CmsEncryptByToken',
                    thumbprints,
                    Convert.objectToBase64(data),
                    Convert.toNullableNumber(hashAlgorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(encAlgorithm));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        cmsEncryptByStore: async (thumbprints, data, hashAlgorithm, mode, encAlgorithm, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsEncrypt');
                await _connection.invoke('CmsEncryptByStore',
                    thumbprints,
                    Convert.objectToBase64(data),
                    Convert.toNullableNumber(hashAlgorithm),
                    Convert.toNullableNumber(mode),
                    Convert.toNullableNumber(encAlgorithm));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        cmsDecryptByToken: async (thumbprint, cipher, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsDecrypt');
                await _connection.invoke('CmsDecryptByToken',
                    thumbprint,
                    Convert.objectToBase64(cipher));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        cmsDecryptByStore: async (thumbprint, cipher, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsDecrypt');
                await _connection.invoke('CmsDecryptByStore',
                    thumbprint,
                    Convert.objectToBase64(cipher));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        cmsSignByToken: async (thumbprint, data = {}, detached = false, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsSign');
                await _connection.invoke('CmsSignByToken',
                    thumbprint,
                    Convert.objectToBase64(data),
                    detached);
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        cmsSignByStore: async (thumbprint, data = {}, detached = false, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsSign');
                await _connection.invoke('CmsSignByStore',
                    thumbprint,
                    Convert.objectToBase64(data),
                    detached);
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        cmsVerifyByToken: async (thumbprint, signedData, originalData = null, validateCertificate = true, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsVerify');
                await _connection.invoke('CmsVerifyByToken',
                    thumbprint,
                    Convert.objectToBase64(signedData),
                    Convert.objectToBase64(originalData),
                    validateCertificate);
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        cmsVerifyByStore: async (thumbprint, signedData, originalData = null, validateCertificate = true, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'cmsVerify');
                await _connection.invoke('CmsVerifyByStore',
                    thumbprint,
                    Convert.objectToBase64(signedData),
                    Convert.objectToBase64(originalData),
                    validateCertificate);
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },

        generateCSR: async (certificateRequest, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'csr');
                await _connection.invoke('GenerateCSR', certificateRequest);
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },

        importToToken: async (ckaId, label, certificate, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'import');
                await _connection.invoke('ImportToToken',
                    ckaId,
                    label,
                    Convert.objectToBase64(certificate));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        importToStore: async (certificate, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'import');
                await _connection.invoke('ImportToStore', Convert.objectToBase64(certificate));
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        exportFromToken: async (thumbprint, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'export');
                await _connection.invoke('ExportFromTokem', thumbprint);
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
        exportFromStore: async (thumbprint, callback) => {
            try {
                _showSpinner();
                _registerCallback(callback, 'export');
                await _connection.invoke('ExportFromStore', thumbprint);
            } catch (err) {
                _hideSpinner();
                console.error(err);
            }
        },
    }
})();