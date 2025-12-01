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

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Result for PIN request with instructions on how to perform login
/// </summary>
public class PinResult
{
    /// <summary>
    /// Flag indicating whether login should be cancelled
    /// </summary>
    [JsonPropertyName("cancel")]
    public bool Cancel { get; }

    /// <summary>
    /// Value of PIN that should be used for the login.
    /// Null value indicates that login should be performed using protected authentication path (e.g. pin pad).
    /// </summary>
    [JsonPropertyName("pin")]
    public string? Pin { get; }

    /// <summary>
    /// Creates new instance of GetPinResult class
    /// </summary>
    /// <param name="cancel">Flag indicating whether login should be cancelled</param>
    /// <param name="pin">Value of PIN that should be used for the login. Null value indicates that login should be performed using protected authentication path (e.g. pin pad).</param>
    public PinResult(bool cancel, string? pin)
    {
        if (cancel && !string.IsNullOrEmpty(pin))
            throw new ArgumentException("PIN value provided along with the request to cancel login");

        Cancel = cancel;
        Pin = pin;
    }
}
