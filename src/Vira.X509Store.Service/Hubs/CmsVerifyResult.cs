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

using System.Text.Json.Serialization;

namespace Vira.X509Store.Service.Hubs;

/// <summary>
/// Represents the result of a CMS (Cryptographic Message Syntax) signature verification
/// operation suitable for transport over SignalR hubs or HTTP APIs.
/// </summary>
/// <remarks>
/// Consumers should treat the byte arrays as binary data. When serializing to text-based
/// transports ensure binary payloads are encoded (for example base64) by the JSON serializer.
/// <para>
/// - <see cref="Certificates"/> contains zero or more DER-encoded X.509 certificates
///   (each element is a raw byte array in DER format).
/// - <see cref="OriginalData"/> contains the original CMS payload bytes (if returned).
/// - <see cref="Verified"/> indicates whether the signature(s) verification succeeded.
/// </para>
/// </remarks>
public class CmsVerifyResult
{
    /// <summary>
    /// Gets or sets the collection of DER-encoded X.509 certificates returned with the CMS.
    /// Each element is a raw certificate byte array in DER format. May be null if no certificates
    /// were returned or not requested.
    /// </summary>
    [JsonPropertyName("certificates")]
    public byte[][]? Certificates { get; set; }

    /// <summary>
    /// Gets or sets the original CMS payload bytes that were verified (if returned).
    /// May be null when the original data is not available or not requested.
    /// </summary>
    [JsonPropertyName("originalData")]
    public byte[]? OriginalData { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the CMS signature verification succeeded.
    /// True when all required signatures are valid; false otherwise.
    /// </summary>
    [JsonPropertyName("verified")]
    public bool Verified { get; set; }
}
