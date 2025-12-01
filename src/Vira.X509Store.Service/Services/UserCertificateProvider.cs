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
using X509CertificateStore = System.Security.Cryptography.X509Certificates.X509Store;

namespace Vira.X509Store.Service.Services;

/// <summary>
/// Provider for enumerating and retrieving certificates from the current user's personal store.
/// </summary>
public class UserCertificateProvider
{
    /// <summary>
    /// Finds certificates in the current user's personal certificate store using optional criteria.
    /// </summary>
    /// <param name="findType">Optional <c>X509FindType</c> value (as int) that defines the search criterion.</param>
    /// <param name="findValue">Optional value paired with <paramref name="findType"/> (e.g., thumbprint or subject).</param>
    /// <returns>Sequence of <see cref="CertificateDetails"/> constructed from matching certificates.</returns>
    // Expose Windows-only store access. Consumers should guard by OS if necessary.
    public static IEnumerable<CertificateDetails> FindCertificates(int? findType, string? findValue)
    {
        //if (!OperatingSystem.IsWindows())
        //    yield break;

        using var store = new X509CertificateStore(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var certificates = store.Certificates.FindCertificates(findType, findValue);

        foreach (var cert in certificates)
        {
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
    /// Finds a single certificate in the current user's personal store by thumbprint and wraps it
    /// into a PKCS#11-aware certificate for unified operations.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library abstraction to create the wrapper.</param>
    /// <param name="thumbprint">Certificate thumbprint (hex) to search for.</param>
    /// <returns><see cref="Pkcs11.X509Certificate"/> wrapper around the found certificate.</returns>
    /// <exception cref="NullReferenceException">Thrown when no matching certificate is found.</exception>
    public static Pkcs11.X509Certificate FindCertificate(IPKCS11Library pKCS11Lib, string thumbprint)
    {
        using var store = new X509CertificateStore(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var certificate = store.Certificates.FindCertificates(0, thumbprint).FirstOrDefault()
            ?? throw new NullReferenceException("The certificate not found.");
        return new Pkcs11.X509Certificate(certificate, pKCS11Lib);
    }
}