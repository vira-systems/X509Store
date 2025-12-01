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

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Vira.X509Store.Service.X509;

/// <summary>
/// Represents the X.509 Subject Alternative Name (SAN) fields used when creating a certificate request.
/// </summary>
/// <remarks>
/// Each property accepts a comma-separated list of values. The values are trimmed; empty entries are ignored.
/// Unsupported or invalid values (e.g., malformed IPs or URIs) will throw during parsing.
/// </remarks>
public class SubjectAltNames
{
    /// <summary>
    /// Gets or sets one or more DNS names (comma-separated), for example: "example.com, www.example.com".
    /// </summary>
    [JsonPropertyName("dns")]
    public string? DNS { get; set; }

    /// <summary>
    /// Gets or sets one or more IP addresses (comma-separated). Values are parsed using <see cref="IPAddress.Parse(string)"/>.
    /// </summary>
    [JsonPropertyName("ip")]
    public string? IP { get; set; }

    /// <summary>
    /// Gets or sets one or more RFC822 email addresses (comma-separated).
    /// </summary>
    [JsonPropertyName("rfc822")]
    public string? RFC822 { get; set; }

    /// <summary>
    /// Gets or sets one or more User Principal Names (UPN) (comma-separated), for example: "user@domain".
    /// </summary>
    [JsonPropertyName("upn")]
    public string? UPN { get; set; }

    /// <summary>
    /// Gets or sets one or more URIs (comma-separated). Values are parsed using <see cref="Uri"/>.
    /// </summary>
    [JsonPropertyName("uri")]
    public string? URI { get; set; }

    /// <summary>
    /// Builds a <see cref="X509Extension"/> representing the Subject Alternative Name extension from the provided values.
    /// </summary>
    /// <param name="critical">Whether the SAN extension should be marked critical.</param>
    /// <returns>An <see cref="X509Extension"/> for inclusion in a certificate request.</returns>
    public X509Extension ToX509Extension(bool critical = false)
    {
        var builder = new SubjectAlternativeNameBuilder();

        if (!string.IsNullOrEmpty(DNS))
        {
            foreach (var dnsName in DNS.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                builder.AddDnsName(dnsName);
            }
        }
        if (!string.IsNullOrEmpty(IP))
        {
            foreach (var ip in IP.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var ipAddress = IPAddress.Parse(ip);
                builder.AddIpAddress(ipAddress);
            }
        }
        if (!string.IsNullOrEmpty(RFC822))
        {
            foreach (var email in RFC822.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                builder.AddEmailAddress(email);
            }
        }
        if (!string.IsNullOrEmpty(UPN))
        {
            foreach (var upn in UPN.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                builder.AddUserPrincipalName(upn);
            }
        }
        if (!string.IsNullOrEmpty(URI))
        {
            foreach (var url in URI.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var uri = new Uri(url);
                builder.AddUri(uri);
            }
        }

        return builder.Build(critical);
    }
}
