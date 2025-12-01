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
/// Represents an error returned from hub operations (SignalR or API).
/// </summary>
/// <remarks>
/// This simple DTO is serialized to JSON for clients. The <see cref="Code"/>
/// property contains an optional numeric error identifier and <see cref="Message"/>
/// contains a human-readable description suitable for display or logging.
/// </remarks>
public class HubError
{
    /// <summary>
    /// Gets or sets an optional numeric error code describing the failure.
    /// Typical values are service-defined and may be used by clients to branch logic.
    /// </summary>
    [JsonPropertyName("code")]
    public int? Code { get; set; }

    /// <summary>
    /// Gets or sets a human-readable error message describing the problem.
    /// May be null when no message is available.
    /// </summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}
