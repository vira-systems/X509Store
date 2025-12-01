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
/// Generic result wrapper for hub operations (SignalR or HTTP APIs).
/// Encapsulates an optional callback identifier, a data payload, and error information.
/// </summary>
/// <typeparam name="T">The type of the payload returned when the operation succeeds.</typeparam>
public class HubResult<T>
{
    /// <summary>
    /// Gets or sets an optional callback identifier provided by the client to correlate responses.
    /// </summary>
    [JsonPropertyName("callback")]
    public string? Callback { get; set; }

    /// <summary>
    /// Gets or sets the data payload returned on success. May be null for operations without data.
    /// </summary>
    [JsonPropertyName("data")]
    public T? Data { get; set; }

    /// <summary>
    /// Gets or sets the error information when the operation fails. When non-null, the result did not succeed.
    /// </summary>
    [JsonPropertyName("error")]
    public HubError? Error { get; set; }

    /// <summary>
    /// Gets a value indicating whether the operation succeeded (i.e., no error is present).
    /// </summary>
    [JsonPropertyName("succeeded")]
    public bool Succeeded => Error == null;

    /// <summary>
    /// Creates a successful result with the specified payload and optional callback identifier.
    /// </summary>
    /// <param name="data">The payload to return to the caller.</param>
    /// <param name="callback">Optional callback identifier to echo back to the client.</param>
    /// <returns>A new <see cref="HubResult{T}"/> representing a successful outcome.</returns>
    internal static HubResult<T> Success(T? data, string? callback = null)
    {
        return new HubResult<T>
        {
            Callback = callback,
            Data = data
        };
    }

    /// <summary>
    /// Creates a failure result from an exception. If the exception is PKCS#11-related,
    /// a friendly message and code are extracted; otherwise, the exception message is used.
    /// </summary>
    /// <param name="ex">The exception that caused the failure.</param>
    /// <returns>A <see cref="HubResult{T}"/> containing an appropriate <see cref="HubError"/>.</returns>
    public static HubResult<T> Failure(Exception ex)
    {
        // If this is PKCS#11 related, return friendly message
        var friendly = ex.GetFriendlyMessage();
        if (!string.IsNullOrWhiteSpace(friendly) && friendly != ex.Message)
        {
            return HubResult<T>.Failure(ex.GetPkcs11ErrorCode(), friendly);
        }

        // Default behavior uses existing exception message
        return HubResult<T>.Failure(ex.GetPkcs11ErrorCode(), ex.GetFriendlyMessage() ?? "An error occurred.");
    }

    /// <summary>
    /// Creates a failure result from an explicit error code and message.
    /// </summary>
    /// <param name="code">Numeric error code describing the failure (service-defined).</param>
    /// <param name="message">Human-readable error message for display or logging.</param>
    /// <returns>A <see cref="HubResult{T}"/> containing an <see cref="HubError"/>.</returns>
    public static HubResult<T> Failure(int code, string message)
    {
        return new HubResult<T>
        {
            Error = new HubError
            {
                Code = code,
                Message = message
            }
        };
    }
}