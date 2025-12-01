using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Vira.X509Store.X509;

public class SubjectAltNames
{
    [JsonPropertyName("dns")]
    public string? DNS { get; set; }

    [JsonPropertyName("ip")]
    public string? IP { get; set; }

    [JsonPropertyName("rfc822")]
    public string? RFC822 { get; set; }

    [JsonPropertyName("upn")]
    public string? UPN { get; set; }

    [JsonPropertyName("uri")]
    public string? URI { get; set; }

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
