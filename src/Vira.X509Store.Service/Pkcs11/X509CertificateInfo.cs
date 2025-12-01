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

using System.Security.Cryptography.X509Certificates;

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Detailed information about X.509 certificate stored on PKCS#11 token
/// </summary>
public class X509CertificateInfo
{
    /// <summary>
    /// Hex encoded identifier of PKCS#11 certificate object (value of CKA_ID attribute)
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Label of PKCS#11 certificate object (value of CKA_LABEL attribute)
    /// </summary>
    public string Label { get; }

    /// <summary>
    /// DER encoded value of X.509 certificate (value of CKA_VALUE attribute)
    /// </summary>
    public byte[] RawData { get; }

    /// <summary>
    /// X.509 certificate parsed as System.Security.Cryptography.X509Certificates.X509Certificate2 instance for convenience
    /// </summary>
    public X509Certificate2 ParsedCertificate { get; }

    /// <summary>
    /// The thumbprint of the parsed certificate.
    /// </summary>
    public string Thumbprint { get; }

    /// <summary>
    /// Type of certified asymmetric key
    /// </summary>
    public AsymmetricKeyType KeyType { get; } = AsymmetricKeyType.Other;

    /// <summary>
    /// Creates new instance of Pkcs11X509CertificateInfo class
    /// </summary>
    /// <param name="ckaId">Value of CKA_ID attribute</param>
    /// <param name="ckaLabel">Value of CKA_LABEL attribute</param>
    /// <param name="ckaValue">Value of CKA_VALUE attribute</param>
    internal X509CertificateInfo(string ckaId, string ckaLabel, byte[] ckaValue)
    {
        Id = ckaId;
        Label = ckaLabel;
        RawData = ckaValue ?? throw new ArgumentNullException(nameof(ckaValue));
#if NET8_0
        ParsedCertificate = new X509Certificate2(RawData);
#else
        ParsedCertificate = X509CertificateLoader.LoadCertificate(RawData);
#endif
        Thumbprint = ParsedCertificate.Thumbprint;

        if (ParsedCertificate.PublicKey.Oid.Value == "1.2.840.113549.1.1.1")
            KeyType = AsymmetricKeyType.RSA;
        else if (ParsedCertificate.PublicKey.Oid.Value == "1.2.840.10045.2.1")
            KeyType = AsymmetricKeyType.EC;
        else
            KeyType = AsymmetricKeyType.Other;
    }
}
