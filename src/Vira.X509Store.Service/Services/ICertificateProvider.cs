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

using Vira.X509Store.Service.Pkcs11;

namespace Vira.X509Store.Service.Services;

/// <summary>
/// Abstraction for locating and retrieving X.509 certificates from different backing stores
/// (e.g. PKCS#11 token, current user store, combined sources).
/// </summary>
public interface ICertificateProvider
{
    /// <summary>
    /// Finds certificates in the specified <paramref name="store"/> using optional find criteria.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library abstraction used for token access.</param>
    /// <param name="store">Store type to search (token, current user, combined).</param>
    /// <param name="findType">Optional X509FindType value (as int) determining search semantics.</param>
    /// <param name="findValue">Optional value paired with <paramref name="findType"/> (thumbprint, subject name, etc.).</param>
    /// <param name="callback">Opaque client callback identifier to echo in results.</param>
    /// <returns>Collection of certificate detail models describing located certificates.</returns>
    IEnumerable<CertificateDetails> FindCertificates(IPKCS11Library pKCS11Lib, StoreType store, int? findType, string? findValue, string callback);

    /// <summary>
    /// Finds a single certificate by thumbprint in the specified <paramref name="store"/>.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library abstraction used for token access.</param>
    /// <param name="store">Store type to search.</param>
    /// <param name="thumbprint">Certificate thumbprint (hex) to match.</param>
    /// <returns>PKCS#11 certificate wrapper if found, otherwise null reference may be returned by implementer.</returns>
    Pkcs11.X509Certificate FindCertificate(IPKCS11Library pKCS11Lib, StoreType store, string thumbprint);
}