using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Vira.X509Store.X509;

/// <summary>
/// The Certificate Request is used to convey a request for a certificate to a 
/// Certification Authority (CA) for the purposes of X.509 certificate generation.
/// </summary>
[Description("The Certificate Request is used to convey a request for a certificate to a Certification Authority (CA) for the purposes of X.509 certificate generation.")]
public class CertificateRequest
{
    /// <summary>
    /// Gets or sets whether to generate a PKCS#10CSR in PEM format.
    /// </summary>
    [JsonPropertyName("pem")]
    [Description("Gets or sets whether to generate a PKCS#10CSR in PEM format.")]
    public bool PEM { get; set; }

    /// <summary>
    /// Gets or sets certificate key information.
    /// </summary>
    [Required]
    [JsonPropertyName("keyInfo")]
    [Description("Gets or sets certificate key information.")]
    public KeyInfo KeyInfo { get; set; } = null!;

    /// <summary>
    /// Gets or sets the token CSP (Crypto Service Provider).
    /// </summary>
    [JsonPropertyName("csp")]
    [Description("Gets or sets the token CSP (Crypto Service Provider).")]
    public string? CSP { get; set; }

    /// <summary>
    /// Gets or sets certificate subject name.
    /// </summary>
    [Required]
    [JsonPropertyName("subjectDn")]
    [Description("Gets or sets certificate subject distinguished name.")]
    public string SubjectDn { get; set; } = null!;

    /// <summary>
    /// Gets or sets certificate subject alternative names.
    /// </summary>
    [JsonPropertyName("subjectAltNames")]
    [Description("Gets or sets certificate subject alternative names.")]
    public SubjectAltNames? SubjectAltNames { get; set; }

    /// <summary>
    /// Gets or sets URL of certificate revocation list.
    /// </summary>
    [JsonPropertyName("crlUrls")]
    [Description("Gets or sets URL of certificate revocation list.")]
    public IEnumerable<string>? CrlUrls { get; set; }

    /// <summary>
    /// Gets or sets URL of online certificate status protocol.
    /// </summary>
    [JsonPropertyName("ocspUrls")]
    [Description("Gets or sets URL of online certificate status protocol.")]
    public IEnumerable<string>? OcspUrls { get; set; }

    /// <summary>
    /// Gets or sets URL of the certificate policy.
    /// </summary>
    [JsonPropertyName("policyUrls")]
    [Description("Gets or sets URL of the certificate policy.")]
    public IEnumerable<string>? PolicyUrls { get; set; }
}
