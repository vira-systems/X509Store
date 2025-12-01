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
/// Generic container for the result of a PKCS#10 CSR (Certificate Signing Request) generation
/// operation performed against a token or store.
/// </summary>
/// <typeparam name="T">
/// The representation type of the generated PKCS#10 CSR. Common choices are <c>byte[]</c>
/// (DER/ASN.1 bytes) or <c>string</c> (PEM encoded CSR). The service does not impose a format;
/// callers choose the concrete <typeparamref name="T"/> they need.
/// </typeparam>
public class CsrResult<T>
{
    /// <summary>
    /// Gets or sets the token/object identifier (CKA_ID) associated with the key that produced the CSR.
    /// This value can be used to look up or reference the key on the token for later operations.
    /// </summary>
    [JsonPropertyName("ckaId")]
    public string CkaId { get; set; } = null!;

    /// <summary>
    /// Gets or sets the user-visible label of the key or object on the token (CKA_LABEL).
    /// Useful for display or selection in UIs and logs.
    /// </summary>
    [JsonPropertyName("label")]
    public string Label { get; set; } = null!;

    /// <summary>
    /// Gets or sets the generated PKCS#10 CSR in the requested representation (<typeparamref name="T"/>).
    /// For example, when <typeparamref name="T"/> is <c>byte[]</c> this property may contain DER bytes;
    /// when <typeparamref name="T"/> is <c>string</c> it may contain a PEM-encoded CSR.
    /// </summary>
    [JsonPropertyName("pkcs10CSR")]
    public T PKCS10CSR { get; set; } = default!;
}
