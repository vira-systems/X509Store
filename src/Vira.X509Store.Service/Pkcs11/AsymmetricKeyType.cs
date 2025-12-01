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
/// Type of asymmetric key
/// </summary>
public enum AsymmetricKeyType
{
    /// <summary>
    /// Any other (currently unsupported) type
    /// </summary>
    Other,

    /// <summary>
    /// RSA (OID 1.2.840.113549.1.1.1)
    /// </summary>
    RSA,

    /// <summary>
    /// Elliptic Curve (OID 1.2.840.10045.2.1)
    /// </summary>
    EC
}
