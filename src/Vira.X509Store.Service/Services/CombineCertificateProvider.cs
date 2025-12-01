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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Vira.X509Store.Service.Pkcs11;
using X509CertificateStore = System.Security.Cryptography.X509Certificates.X509Store;

namespace Vira.X509Store.Service.Services;

/// <summary>
/// Helper provider that surfaces certificates from the current user store which are backed by
/// a hardware token (PKCS#11). Detection is based on the KSP/CSP provider of the private key.
/// </summary>
public class CombineCertificateProvider
{
    /// <summary>
    /// Finds certificates in the current user store whose private keys are backed by the connected token.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library used to detect connected device/provider information.</param>
    /// <param name="findType">Optional X509FindType value (as int) used to pre-filter user store certificates.</param>
    /// <param name="findValue">Optional search value paired with <paramref name="findType"/>.</param>
    /// <returns>An enumerable of <see cref="CertificateDetails"/> for token-backed user store certificates.</returns>
    public static IEnumerable<CertificateDetails> FindCertificates(IPKCS11Library pKCS11Lib, int? findType, string? findValue)
    {
        pKCS11Lib.LoadConnectedDevice();

        using var store = new X509CertificateStore(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var certificates = store.Certificates.FindCertificates(findType, findValue);
        var tokenCerts = new List<CertificateDetails>();
        var tokenProvider = pKCS11Lib.ConnectedDeviceCSP?.KSP;

        foreach (var cert in certificates)
        {
            if (cert.HasPrivateKey)
            {
                var privateKey = cert.GetRSAPrivateKey();
                if (privateKey is RSACng cngCSP)
                {
                    // Match by CNG Key Storage Provider (KSP)
                    if (tokenProvider?.Equals(cngCSP.Key.Provider!.Provider) == true)
                    {
                        // It's USB Token
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
                else if (OperatingSystem.IsWindows() && privateKey is RSACryptoServiceProvider rsaCSP && rsaCSP.CspKeyContainerInfo.HardwareDevice)
                {
                    // Legacy CSP with hardware-backed key
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
        }
    }

    /// <summary>
    /// Finds a single certificate in the current user store by thumbprint and wraps it for token operations.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library used to build the wrapper for token-aware operations.</param>
    /// <param name="thumbprint">Certificate thumbprint (hex) to locate.</param>
    /// <returns><see cref="Pkcs11.X509Certificate"/> wrapper for the found certificate.</returns>
    /// <exception cref="NullReferenceException">Thrown when the certificate cannot be found.</exception>
    public static Pkcs11.X509Certificate FindCertificate(IPKCS11Library pKCS11Lib,string thumbprint)
    {
        using var store = new X509CertificateStore(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var certificate = store.Certificates.FindCertificates(0, thumbprint).FirstOrDefault()
            ?? throw new NullReferenceException("The certificate not found.");
        return new Pkcs11.X509Certificate(certificate, pKCS11Lib);
    }
}
