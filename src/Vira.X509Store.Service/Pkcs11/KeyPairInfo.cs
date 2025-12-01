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

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Detailed information about PKCS#11 key pair that are typically present in the token (cryptographic device).
/// </summary>
public class KeyPairInfo
{
    /// <summary>
    /// Gets the private key information
    /// </summary>
    public KeyInfo? PrivateKeyInfo { get; internal set; }

    /// <summary>
    /// Gets the public key information
    /// </summary>
    public KeyInfo? PublicKeyInfo { get; internal set; }
}
