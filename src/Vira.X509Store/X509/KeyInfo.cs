using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Vira.X509Store.X509;

/// <summary>
/// Specifies the attributes of an asymmetric key pair.
/// </summary>
[Description("Specifies the attributes of an asymmetric key pair.")]
public class KeyInfo
{
    /// <summary>
    /// Gets or sets the lenght of RSA key.
    /// </summary>
    [JsonPropertyName("keySize")]
    [Description("Gets or sets the lenght of RSA key.")]
    public int? KeySize { get; set; }

    /// <summary>
    /// Gets or sets elliptic curve value for ECDsa key algorithm.
    /// </summary>
    [JsonPropertyName("ellipticCurve")]
    [Description("Gets or sets elliptic curve value for ECDsa key algorithm.")]
    public EllipticCurveFlags? EllipticCurve { get; set; }

    /// <summary>
    /// Gets or sets certificate key usages. The default value is None.
    /// </summary>
    [Required]
    [JsonPropertyName("keyUsages")]
    [Description("Gets or sets certificate key usages. The default value is None.")]
    public X509KeyUsageFlags KeyUsages { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'KeyUsages' extension is critical.
    /// </summary>
    [JsonPropertyName("keyUsageCritical")]
    [Description("Gets or sets whether the certificate 'KeyUsages' extension is critical.")]
    public bool KeyUsageCritical { get; set; }

    /// <summary>
    /// Gets or sets certificate enhanced key usages. The default value is None.
    /// </summary>
    [JsonPropertyName("enhancedKeyUsages")]
    [Description("Gets or sets certificate enhanced key usages. The default value is None.")]
    public X509EnhancedKeyUsageFlags? EnhancedKeyUsages { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'EnhancedKeyUsages' extension is critical.
    /// </summary>
    [JsonPropertyName("enhancedKeyUsageCritical")]
    [Description("Gets or sets whether the certificate 'EnhancedKeyUsages' extension is critical.")]
    public bool EnhancedKeyUsageCritical { get; set; }

    /// <summary>
    /// Gets or sets the certificate signature algorithm.
    /// </summary>
    [Required]
    [JsonPropertyName("signatureAlgorithm")]
    [Description("Gets or sets the certificate signature algorithm.")]
    public SignatureAlgorithms SignatureAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'AuthorityKeyIdentifier' extension is critical.
    /// </summary>
    [JsonPropertyName("authorityKeyIdentifierCritical")]
    [Description("Gets or sets whether the certificate 'AuthorityKeyIdentifier' extension is critical.")]
    public bool AuthorityKeyIdentifierCritical { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'BasicConstraints' extension is critical.
    /// </summary>
    [JsonPropertyName("basicConstraintsCritical")]
    [Description("Gets or sets whether the certificate 'BasicConstraints' extension is critical.")]
    public bool BasicConstraintsCritical { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'CertificatePolicies' extension is critical.
    /// </summary>
    [JsonPropertyName("certificatePoliciesCritical")]
    [Description("Gets or sets whether the certificate 'CertificatePolicies' extension is critical.")]
    public bool CertificatePoliciesCritical { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'CrlDistributionPoint' extension is critical.
    /// </summary>
    [JsonPropertyName("crlDistributionPointCritical")]
    [Description("Gets or sets whether the certificate 'CrlDistributionPoint' extension is critical.")]
    public bool CrlDistributionPointCritical { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'IssuerAlternativeName' extension is critical.
    /// </summary>
    [JsonPropertyName("issuerAlternativeNameCritical")]
    [Description("Gets or sets whether the certificate 'IssuerAlternativeName' extension is critical.")]
    public bool IssuerAlternativeNameCritical { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'SubjectAlternativeName' extension is critical.
    /// </summary>
    [JsonPropertyName("subjectAlternativeNameCritical")]
    [Description("Gets or sets whether the certificate 'SubjectAlternativeName' extension is critical.")]
    public bool SubjectAlternativeNameCritical { get; set; }

    /// <summary>
    /// Gets or sets whether the certificate 'SubjectKeyidentIfier' extension is critical.
    /// </summary>
    [JsonPropertyName("subjectKeyIdentifierCritical")]
    [Description("Gets or sets whether the certificate 'SubjectKeyidentIfier' extension is critical.")]
    public bool SubjectKeyIdentifierCritical { get; set; }
}
