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

namespace Vira.X509Store.Service;

/// <summary>
/// Describes a cryptographic service/provider and platform-specific library locations.
/// </summary>
/// <remarks>
/// This class holds both legacy CryptoAPI provider information (CSP) and newer CNG/KSP names,
/// plus optional native PKCS#11 library paths for Linux/macOS/Windows. The <see cref="Type"/>
/// property uses the <see cref="ProviderType"/> enum to indicate the provider type (RSA, ECDSA, etc.).
/// </remarks>
public class CspInfo
{
    /// <summary>
    /// Gets or sets the friendly display name for the provider configuration.
    /// </summary>
    public string Name { get; set; } = null!;

    /// <summary>
    /// Gets or sets the Crypto Service Provider (CSP) name used on Windows legacy APIs.
    /// </summary>
    public string CSP { get; set; } = null!;

    /// <summary>
    /// Gets or sets the Key Storage Provider (KSP) name used by CNG (Cryptography Next Generation).
    /// </summary>
    public string KSP { get; set; } = null!;

    /// <summary>
    /// Gets or sets the provider type indicating the crypto algorithm family supported by this provider.
    /// </summary>
    public ProviderType Type { get; set; }

    /// <summary>
    /// Gets or sets the path to the native PKCS#11 library to use on Linux (shared object).
    /// </summary>
    public string LnxLib { get; set; } = null!;

    /// <summary>
    /// Gets or sets the path to the native PKCS#11 library to use on macOS (dylib).
    /// </summary>
    public string MacLib { get; set; } = null!;

    /// <summary>
    /// Gets or sets the path to the native PKCS#11 library or provider DLL to use on Windows.
    /// </summary>
    public string WinLib { get; set; } = null!;
}
