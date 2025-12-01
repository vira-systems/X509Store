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

namespace Vira.X509Store.Service.Services;

/// <summary>
/// Immutable DTO describing an X.509 certificate discovered in a store or token.
/// </summary>
/// <param name="Thumbprint">Hex thumbprint of the certificate (case-insensitive).</param>
/// <param name="CommonName">Common Name (CN) extracted from the subject, when available.</param>
/// <param name="Subject">Full subject distinguished name.</param>
/// <param name="Issuer">Issuer distinguished name.</param>
/// <param name="SerialNumber">Certificate serial number (hex string).</param>
/// <param name="NotBefore">Validity period start (UTC/local as provided).</param>
/// <param name="NotAfter">Validity period end (UTC/local as provided).</param>
/// <param name="FriendlyName">Optional friendly display name, if available from the store.</param>
/// <param name="HasPrivateKey">True if the private key is present and accessible.</param>
public record CertificateDetails(
    string Thumbprint,
    string CommonName,
    string Subject,
    string Issuer,
    string SerialNumber,
    DateTime NotBefore,
    DateTime NotAfter,
    string FriendlyName,
    bool HasPrivateKey);
