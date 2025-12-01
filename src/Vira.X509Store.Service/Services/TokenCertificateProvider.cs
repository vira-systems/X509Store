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
using Vira.X509Store.Service.Pkcs11;

namespace Vira.X509Store.Service.Services;

/// <summary>
/// Provider for listing and retrieving certificates that reside on a connected PKCS#11 token.
/// Uses <see cref="IPKCS11Library"/> to access the token and surface certificate metadata.
/// </summary>
public class TokenCertificateProvider
{
    /// <summary>
    /// Enumerates certificates available on the connected token and applies optional find criteria.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library abstraction used to access the token.</param>
    /// <param name="findType">Optional <c>X509FindType</c> value (as int) used to filter certificates.</param>
    /// <param name="findValue">Optional search value paired with <paramref name="findType"/>.</param>
    /// <returns>Sequence of <see cref="CertificateDetails"/> describing token certificates.</returns>
    // Minimal token provider wrapper. Expand to integrate your PKCS11 library.
    public static IEnumerable<CertificateDetails> FindCertificates(IPKCS11Library pKCS11Lib, int? findType, string? findValue)
    {
        pKCS11Lib.LoadConnectedDevice();
        var certs = pKCS11Lib.Token?.Certificates;
        if (certs == null || certs.Count == 0)
            yield break;

        var x509Certificates = new X509Certificate2Collection();
        x509Certificates.AddRange(certs.Select(e => e.Info.ParsedCertificate).ToArray());
        var certificates = x509Certificates.FindCertificates(findType, findValue);

        foreach (var cert in certificates)
        {
            //var certId = certs
            //    .FirstOrDefault(e => e.Info.Thumbprint.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase))?.Info.Id;
            yield return new CertificateDetails(
                cert.Thumbprint ?? string.Empty,
                cert.GetNameInfo(X509NameType.SimpleName, false) ?? string.Empty,
                cert.Subject ?? string.Empty,
                cert.Issuer ?? string.Empty,
                cert.SerialNumber,
                cert.NotBefore,
                cert.NotAfter,
                cert.FriendlyName ?? string.Empty,
                cert.HasPrivateKey);
        }
    }

    /// <summary>
    /// Finds a certificate on the connected token by its thumbprint.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library abstraction used to access the token.</param>
    /// <param name="thumbprint">Certificate thumbprint (hex, case-insensitive).</param>
    /// <returns>Token-backed certificate wrapper.</returns>
    /// <exception cref="NullReferenceException">Thrown when the certificate cannot be found on the token.</exception>
    public static Pkcs11.X509Certificate FindCertificate(IPKCS11Library pKCS11Lib, string thumbprint)
    {
        pKCS11Lib.LoadConnectedDevice();

        return pKCS11Lib.Token?.Certificates
            .SingleOrDefault(e => e.Info.Thumbprint.Equals(thumbprint))
            ?? throw new NullReferenceException("The certificate not found.");
    }
}