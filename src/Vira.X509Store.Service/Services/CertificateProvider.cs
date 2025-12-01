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
/// Default implementation of <see cref="ICertificateProvider"/> that delegates
/// certificate lookup operations to token, user store, or a combined provider
/// based on the requested <see cref="StoreType"/>.
/// </summary>
public class CertificateProvider : ICertificateProvider
{
    /// <summary>
    /// Finds certificates according to the specified store source and optional search criteria.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library abstraction used when accessing token-backed stores.</param>
    /// <param name="store">Target store to search (token, current user, or combined).</param>
    /// <param name="findType">Optional <c>X509FindType</c> value (as int) that controls search semantics.</param>
    /// <param name="findValue">Optional search value paired with <paramref name="findType"/>.</param>
    /// <param name="callback">Opaque client callback identifier to be echoed in results.</param>
    /// <returns>Enumerable of <see cref="CertificateDetails"/> describing matching certificates.</returns>
    public IEnumerable<CertificateDetails> FindCertificates(IPKCS11Library pKCS11Lib, StoreType store, int? findType, string? findValue, string callback)
    {
        if (store == StoreType.HardToken)
            return TokenCertificateProvider.FindCertificates(pKCS11Lib, findType, findValue);
        else if (store == StoreType.CurrentUser)
            return UserCertificateProvider.FindCertificates(findType, findValue);
        else
            return CombineCertificateProvider.FindCertificates(pKCS11Lib, findType, findValue);
    }

    /// <summary>
    /// Finds a single certificate by thumbprint from the requested store source.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library abstraction used when accessing token-backed stores.</param>
    /// <param name="store">Target store to search (token, current user, or combined).</param>
    /// <param name="thumbprint">Certificate thumbprint (hex) to locate.</param>
    /// <returns>Wrapper around the located certificate; provider throws if not found.</returns>
    public Pkcs11.X509Certificate FindCertificate(IPKCS11Library pKCS11Lib, StoreType store, string thumbprint)
    {
        if (store == StoreType.HardToken)
            return TokenCertificateProvider.FindCertificate(pKCS11Lib, thumbprint);
        else if (store == StoreType.CurrentUser)
            return UserCertificateProvider.FindCertificate(pKCS11Lib, thumbprint);
        else
            return CombineCertificateProvider.FindCertificate(pKCS11Lib, thumbprint);
    }
}