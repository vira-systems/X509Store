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

using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Internal context for Pkcs11X509Certificate2 class
/// </summary>
internal class X509CertificateContext
{
    /// <summary>
    /// Detailed information about X.509 certificate stored on PKCS#11 token
    /// </summary>
    internal X509CertificateInfo CertificateInfo { get; }

    /// <summary>
    /// High level PKCS#11 object handle of certificate object
    /// </summary>
    internal IObjectHandle CertHandle { get; }

    /// <summary>
    /// High level PKCS#11 object handle of private key object
    /// </summary>
    internal IObjectHandle? PrivKeyHandle { get; set; }

    /// <summary>
    /// High level PKCS#11 object handle of public key object
    /// </summary>
    internal IObjectHandle? PubKeyHandle { get; set; }

    /// <summary>
    /// Flag indicating whether key usage requires context specific login to be performed
    /// </summary>
    internal bool KeyUsageRequiresLogin { get; } = false;

    /// <summary>
    /// Internal context for Pkcs11Token class
    /// </summary>
    internal TokenContext TokenContext { get; }

    /// <summary>
    /// Creates new instance of Pkcs11X509Certificate2Context class
    /// </summary>
    /// <param name="certificateInfo">Detailed information about X.509 certificate stored on PKCS#11 token</param>
    /// <param name="certHandle">High level PKCS#11 object handle of certificate object</param>
    /// <param name="privKeyHandle">High level PKCS#11 object handle of private key object</param>
    /// <param name="pubKeyHandle">High level PKCS#11 object handle of public key object</param>
    /// <param name="keyUsageRequiresLogin">Flag indicating whether key usage requires context specific login to be performed</param>
    /// <param name="tokenContext">Internal context for Pkcs11Token class</param>
    internal X509CertificateContext(X509CertificateInfo certificateInfo,
                                    IObjectHandle certHandle,
                                    IObjectHandle? privKeyHandle,
                                    IObjectHandle? pubKeyHandle,
                                    bool keyUsageRequiresLogin,
                                    TokenContext tokenContext)
    {
        CertificateInfo = certificateInfo ?? throw new ArgumentNullException(nameof(certificateInfo));
        CertHandle = certHandle ?? throw new ArgumentNullException(nameof(certHandle));
        PrivKeyHandle = privKeyHandle;
        PubKeyHandle = pubKeyHandle;
        KeyUsageRequiresLogin = keyUsageRequiresLogin;
        TokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    }
}
