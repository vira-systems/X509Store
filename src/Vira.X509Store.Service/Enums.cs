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

using System.ComponentModel;
using System.Text.Json.Serialization;

namespace Vira.X509Store.Service;

/// <summary>
/// Enumerations related to cryptographic primitives, providers and certificate attributes
/// used by the X509 store service.
/// </summary>
/// <remarks>
/// This file centralizes enums for curves, hash algorithms, provider types, encryption and
/// signature algorithms, subject DN attributes, store types and extended key usages.
/// </remarks>

/// <summary>
/// Elliptic curve identifiers used by the service. Values map to well-known named curves
/// and are used to indicate which EC curve is expected or supported by providers and keys.
/// </summary>
public enum EllipticCurveFlags
{
    /// <summary>
    /// Any Elliptic Curve (no restriction).
    /// </summary>
    [Description("Any Elliptic Curve")]
    ANY_EC_CURVE = 0,

    /// <summary>
    /// brainpoolP160r1 (OID: 1.3.36.3.3.2.8.1.1.1)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.1")]
    brainpoolP160r1 = 1,

    /// <summary>
    /// brainpoolP160t1 (OID: 1.3.36.3.3.2.8.1.1.2)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.2")]
    brainpoolP160t1 = 2,

    /// <summary>
    /// brainpoolP192r1 (OID: 1.3.36.3.3.2.8.1.1.3)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.3")]
    brainpoolP192r1 = 3,

    /// <summary>
    /// brainpoolP192t1 (OID: 1.3.36.3.3.2.8.1.1.4)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.4")]
    brainpoolP192t1 = 4,

    /// <summary>
    /// brainpoolP224r1 (OID: 1.3.36.3.3.2.8.1.1.5)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.5")]
    brainpoolP224r1 = 5,

    /// <summary>
    /// brainpoolP224t1 (OID: 1.3.36.3.3.2.8.1.1.6)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.6")]
    brainpoolP224t1 = 6,

    /// <summary>
    /// brainpoolP256r1 (OID: 1.3.36.3.3.2.8.1.1.7)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.7")]
    brainpoolP256r1 = 7,

    /// <summary>
    /// brainpoolP256t1 (OID: 1.3.36.3.3.2.8.1.1.8)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.8")]
    brainpoolP256t1 = 8,

    /// <summary>
    /// brainpoolP320r1 (OID: 1.3.36.3.3.2.8.1.1.9)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.9")]
    brainpoolP320r1 = 9,

    /// <summary>
    /// brainpoolP320t1 (OID: 1.3.36.3.3.2.8.1.1.10)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.10")]
    brainpoolP320t1 = 10,

    /// <summary>
    /// brainpoolP384r1 (OID: 1.3.36.3.3.2.8.1.1.11)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.11")]
    brainpoolP384r1 = 11,

    /// <summary>
    /// brainpoolP384t1 (OID: 1.3.36.3.3.2.8.1.1.12)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.12")]
    brainpoolP384t1 = 12,

    /// <summary>
    /// brainpoolP512r1 (OID: 1.3.36.3.3.2.8.1.1.13)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.13")]
    brainpoolP512r1 = 13,

    /// <summary>
    /// brainpoolP512t1 (OID: 1.3.36.3.3.2.8.1.1.14)
    /// </summary>
    [Description("1.3.36.3.3.2.8.1.1.14")]
    brainpoolP512t1 = 14,

    /// <summary>
    /// NIST P-256 (OID: 1.2.840.10045.3.1.7)
    /// </summary>
    [Description("1.2.840.10045.3.1.7")]
    nistP256 = 256,

    /// <summary>
    /// NIST P-384 (OID: 1.3.132.0.34)
    /// </summary>
    [Description("1.3.132.0.34")]
    nistP384 = 384,

    /// <summary>
    /// NIST P-521 (OID: 1.3.132.0.35)
    /// </summary>
    [Description("1.3.132.0.35")]
    nistP521 = 521,
}

/// <summary>
/// Identifies supported hash algorithms. Description attributes contain the algorithm OID.
/// </summary>
public enum HashAlgorithmFlags
{
    /// <summary>
    /// MD5 (OID: 1.2.840.113549.2.5) — legacy, not recommended for new systems.
    /// </summary>
    [Description("1.2.840.113549.2.5")]
    MD5,

    /// <summary>
    /// SHA-1 (OID: 1.3.14.3.2.26) — legacy, consider using SHA-2 or SHA-3.
    /// </summary>
    [Description("1.3.14.3.2.26")]
    SHA1,

    /// <summary>
    /// SHA-224 (OID: 2.16.840.1.101.3.4.2.4).
    /// </summary>
    [Description("2.16.840.1.101.3.4.2.4")]
    SHA224,

    /// <summary>
    /// SHA-256 (OID: 2.16.840.1.101.3.4.2.1).
    /// </summary>
    [Description("2.16.840.1.101.3.4.2.1")]
    SHA256,

    /// <summary>
    /// SHA-384 (OID: 2.16.840.1.101.3.4.2.2).
    /// </summary>
    [Description("2.16.840.1.101.3.4.2.2")]
    SHA384,

    /// <summary>
    /// SHA-512 (OID: 2.16.840.1.101.3.4.2.3).
    /// </summary>
    [Description("2.16.840.1.101.3.4.2.3")]
    SHA512,

    /// <summary>
    /// SHA3-256 (OID: 2.16.840.1.101.3.4.2.8).
    /// </summary>
    [Description("2.16.840.1.101.3.4.2.8")]
    SHA3_256,

    /// <summary>
    /// SHA3-384 (OID: 2.16.840.1.101.3.4.2.9).
    /// </summary>
    [Description("2.16.840.1.101.3.4.2.9")]
    SHA3_384,

    /// <summary>
    /// SHA3-512 (OID: 2.16.840.1.101.3.4.2.10).
    /// </summary>
    [Description("2.16.840.1.101.3.4.2.10")]
    SHA3_512,
}

/// <summary>
/// PIN types for cryptographic tokens.
/// </summary>
public enum PinType
{
    /// <summary>
    /// The key PIN.
    /// </summary>
    KeyPin = 0,

    /// <summary>
    /// The token PIN.
    /// </summary>
    TokenPin = 1,
}

/// <summary>
/// Crypto provider types used by legacy Windows CryptoAPI and for documentation mapping.
/// Values correspond to provider type identifiers used in native APIs.
/// </summary>
public enum ProviderType : uint
{
    /// <summary>
    /// The PROV_RSA_FULL provider type supports both digital signatures and data encryption.
    /// It is considered a general purpose CSP. The RSA public-key algorithm is used for all
    /// public-key operations.
    /// </summary>
    PROV_RSA_FULL = 1,

    /// <summary>
    /// The PROV_RSA_SIG provider type is a subset of PROV_RSA_FULL.
    /// It supports only those functions and algorithms required for hashes and digital signatures.
    /// </summary>
    PROV_RSA_SIG = 2,

    /// <summary>
    /// The PROV_DSS provider type, like PROV_RSA_SIG, only supports hashes and digital signatures.
    /// The signature algorithm specified by the PROV_DSS provider type is the Digital Signature
    /// Algorithm (DSA).
    /// </summary>
    PROV_DSS = 3,

    /// <summary>
    /// The PROV_FORTEZZA provider type contains a set of cryptographic protocols and algorithms owned
    /// by the National Institute of Standards and Technology (NIST).
    /// </summary>
    PROV_FORTEZZA = 4,

    /// <summary>
    /// The PROV_MS_EXCHANGE provider type is designed for the cryptographic needs of the Microsoft
    /// Exchange mail application and other applications compatible with Microsoft Mail.
    /// </summary>
    PROV_MS_EXCHANGE = 5,

    /// <summary>
    /// The PROV_SSL provider type supports the Secure Sockets Layer (SSL) protocol.
    /// </summary>
    PROV_SSL = 6,

    /// <summary>
    /// The PROV_RSA_SCHANNEL provider type supports both RSA and Schannel protocols.
    /// </summary>
    PROV_RSA_SCHANNEL = 12,

    /// <summary>
    /// The PROV_DSS_DH provider is a superset of the PROV_DSS provider type.
    /// </summary>
    PROV_DSS_DH = 13,

    /// <summary>
    /// The PROV_EC_ECDSA_SIG provider type supports the ECDSA Signature protocol.
    /// </summary>
    PROV_EC_ECDSA_SIG = 14,

    /// <summary>
    /// The PROV_EC_ECNRA_SIG provider type supports the ECNRA Signature protocol.
    /// </summary>
    PROV_EC_ECNRA_SIG = 15,

    /// <summary>
    /// The PROV_EC_ECDSA_FULL provider type supports both digital signatures and data encryption.
    /// </summary>
    PROV_EC_ECDSA_FULL = 16,

    /// <summary>
    /// PROV_EC_ECNRA_FULL: Full EC provider (NIST R/A) supporting both encryption and signatures.
    /// </summary>
    PROV_EC_ECNRA_FULL = 17,

    /// <summary>
    /// PROV_DH_SCHANNEL: Diffie-Hellman provider with Schannel support.
    /// </summary>
    PROV_DH_SCHANNEL = 18,

    /// <summary>
    /// PROV_SPYRUS_LYNKS: Vendor-specific/undocumented provider identifier.
    /// </summary>
    PROV_SPYRUS_LYNKS = 20,

    /// <summary>
    /// PROV_RNG: Random number generator provider (vendor/implementation-specific).
    /// </summary>
    PROV_RNG = 21,

    /// <summary>
    /// PROV_INTEL_SEC: Intel security provider (vendor-specific).
    /// </summary>
    PROV_INTEL_SEC = 22,

    /// <summary>
    /// PROV_REPLACE_OWF: Replacement one-way function provider (legacy/vendor-specific).
    /// </summary>
    PROV_REPLACE_OWF = 23,

    /// <summary>
    /// PROV_RSA_AES: RSA provider with AES support (modern provider for RSA + AES).
    /// </summary>
    PROV_RSA_AES = 24,
}

/// <summary>
/// Symmetric encryption algorithms supported by the service.
/// </summary>
public enum EncryptionAlgorithm
{
    /// <summary>
    /// RC2 in CBC mode (1.2.840.113549.3.2) (legacy).
    /// </summary>
    RC2,

    /// <summary>
    /// RC4 stream cipher (1.2.840.113549.3.4) (legacy, not recommended).
    /// </summary>
    RC4,

    /// <summary>
    /// Triple DES (3DES / DES-EDE) in CBC mode (1.2.840.113549.3.7).
    /// </summary>
    TripleDES,

    /// <summary>
    /// DES in CBC mode (1.3.14.3.2.7) (legacy, insecure).
    /// </summary>
    DES,

    /// <summary>
    /// AES-128 in CBC mode (2.16.840.1.101.3.4.1.2).
    /// </summary>
    AES128,

    /// <summary>
    /// AES-192 in CBC mode (2.16.840.1.101.3.4.1.22).
    /// </summary>
    AES192,

    /// <summary>
    /// AES-256 in CBC mode (2.16.840.1.101.3.4.1.42).
    /// </summary>
    AES256,
}

/// <summary>
/// Signature algorithm enumeration. Description attributes reference OIDs defined in <c>Oids</c>.
/// </summary>
public enum SignatureAlgorithms
{
    /// <summary>
    /// No signature algorithm selected.
    /// </summary>
    [Description("No Signature Algorithm")]
    None,

    /// <summary>
    /// SHA-1 with RSA (OID: 1.2.840.113549.1.1.5).
    /// </summary>
    [Description(Oids.RsaPkcs1Sha1)]
    SHA1WithRSA,

    /// <summary>
    /// SHA-256 with RSA (OID: 1.2.840.113549.1.1.11).
    /// </summary>
    [Description(Oids.RsaPkcs1Sha256)]
    SHA256WithRSA,

    /// <summary>
    /// SHA-384 with RSA (OID: 1.2.840.113549.1.1.12).
    /// </summary>
    [Description(Oids.RsaPkcs1Sha384)]
    SHA384WithRSA,

    /// <summary>
    /// SHA-512 with RSA (OID: 1.2.840.113549.1.1.13).
    /// </summary>
    [Description(Oids.RsaPkcs1Sha512)]
    SHA512WithRSA,

    /// <summary>
    /// SHA-1 with ECDSA (OID: 1.2.840.10045.4.1).
    /// </summary>
    [Description(Oids.ECDsaWithSha1)]
    SHA1WithECDSA,

    /// <summary>
    /// SHA-224 with ECDSA (OID: 1.2.840.10045.4.3.1).
    /// </summary>
    [Description(Oids.ECDsaWithSha224)]
    SHA224WithECDSA,

    /// <summary>
    /// SHA-256 with ECDSA (OID: 1.2.840.10045.4.3.2).
    /// </summary>
    [Description(Oids.ECDsaWithSha256)]
    SHA256WithECDSA,

    /// <summary>
    /// SHA-384 with ECDSA (OID: 1.2.840.10045.4.3.3).
    /// </summary>
    [Description(Oids.ECDsaWithSha384)]
    SHA384WithECDSA,

    /// <summary>
    /// SHA-512 with ECDSA (OID: 1.2.840.10045.4.3.4).
    /// </summary>
    [Description(Oids.ECDsaWithSha512)]
    SHA512WithECDSA,
}

/// <summary>
/// Certificate distinguished name attribute identifiers used by the service.
/// Serialized as strings when using System.Text.Json because of the JsonStringEnumConverter attribute.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<SubjectDns>))]
public enum SubjectDns
{
    /// <summary>
    /// E-mail address (E) in DN
    /// </summary>
    [Description("E-mail address (E) in DN")]
    E = 3,

    /// <summary>
    /// Unique ID (UID)
    /// </summary>
    [Description("Unique ID (UID)")]
    UID = 4,

    /// <summary>
    /// Common Name (CN)
    /// </summary>
    [Description("Common Name (CN)")]
    CN = 5,

    /// <summary>
    /// Serial number
    /// </summary>
    [Description("Serial number")]
    SERIALNUMBER = 6,

    /// <summary>
    /// Given name
    /// </summary>
    [Description("Given name")]
    GIVENNAME = 7,

    /// <summary>
    /// Initials
    /// </summary>
    [Description("Initials")]
    INITIALS = 8,

    /// <summary>
    /// Surname
    /// </summary>
    [Description("Surname")]
    SN = 9,

    /// <summary>
    /// Title (T)
    /// </summary>
    [Description("Title (T)")]
    T = 10,

    /// <summary>
    /// Organizational Unit (OU)
    /// </summary>
    [Description("Organizational Unit (OU)")]
    OU = 11,

    /// <summary>
    /// Organization (O)
    /// </summary>
    [Description("Organization (O)")]
    O = 12,

    /// <summary>
    /// Locality (L)
    /// </summary>
    [Description("Locality (L)")]
    L = 13,

    /// <summary>
    /// State or province (ST)
    /// </summary>
    [Description("State or province (ST)")]
    ST = 14,

    /// <summary>
    /// Domain Component (DC)
    /// </summary>
    [Description("Domain Component (DC)")]
    DC = 15,

    /// <summary>
    /// Country (C)
    /// </summary>
    [Description("Country (C)")]
    C = 16,

    /// <summary>
    /// Unstructured address (IP)
    /// </summary>
    [Description("Unstructured address (IP)")]
    UNSTRUCTUREDADDRESS = 39,

    /// <summary>
    /// Unstructured name (FQDN)
    /// </summary>
    [Description("Unstructured name (FQDN)")]
    UNSTRUCTUREDNAME = 40,

    /// <summary>
    /// DN Qualifier
    /// </summary>
    [Description("DN Qualifier")]
    DN = 47,

    /// <summary>
    /// Business category
    /// </summary>
    [Description("Business category")]
    BUSINESSCATEGORY = 48,

    /// <summary>
    /// Postal code
    /// </summary>
    [Description("Postal code")]
    POSTALCODE = 49,

    /// <summary>
    /// Postal address
    /// </summary>
    [Description("Postal address (OID: 2.5.4.16)")]
    POSTALADDRESS = 50,

    /// <summary>
    /// Phone number
    /// </summary>
    [Description("Phone number (PHONE/TELEPHONENUMBER)")]
    PHONE = 51,

    /// <summary>
    /// Pseudonym
    /// </summary>
    [Description("Pseudonym")]
    PSEUDONYM = 53,

    /// <summary>
    /// Street
    /// </summary>
    [Description("Street")]
    STREET = 54,

    /// <summary>
    /// Name
    /// </summary>
    [Description("Name")]
    NAME = 55,

    /// <summary>
    /// Description
    /// </summary>
    [Description("Description")]
    DESCRIPTION = 60,

    /// <summary>
    /// UniqueIdentifier
    /// </summary>
    [Description("UniqueIdentifier")]
    UNIQUEIDENTIFIER = 62,

    /// <summary>
    /// Role
    /// </summary>
    [Description("Role")]
    ROLE = 70,

    /// <summary>
    /// Organization Identifier (OID: 2.5.4.97)
    /// </summary>
    [Description("Organization Identifier")]
    ORGANIZATIONIDENTIFIER = 106,
}

/// <summary>
/// Type of certificate store used for lookups and storage operations.
/// </summary>
public enum StoreType
{
    /// <summary>
    /// Hardware token (smart card / HSM).
    /// </summary>
    HardToken = 0,

    /// <summary>
    /// Current user's personal certificate store.
    /// </summary>
    CurrentUser = 1,

    /// <summary>
    /// Combine both hardware token and current user store for search operations.
    /// </summary>
    Combine = 2,
}

/// <summary>
/// Enhanced/Extended Key Usage (EKU) flags for X.509 certificates.
/// This enum is marked with <see cref="FlagsAttribute"/> so multiple values can be combined.
/// </summary>
[Flags]
public enum X509EnhancedKeyUsageFlags
{
    /// <summary>
    /// No enhanced key usage specified.
    /// </summary>
    [Description("None")]
    None = 0,

    /// <summary>
    /// Any Extended Key Usage (OID: 2.5.29.37.0).
    /// </summary>
    [Description("Any Extended Key Usage")]
    AnyExtendedKeyUsage = 1,

    /// <summary>
    /// Server Authentication (OID: 1.3.6.1.5.5.7.3.1).
    /// </summary>
    [Description("Server Authentication")]
    ServerAuthentication = 2,

    /// <summary>
    /// Client Authentication (OID: 1.3.6.1.5.5.7.3.2).
    /// </summary>
    [Description("Client Authentication")]
    ClientAuthentication = 4,

    /// <summary>
    /// Code Signing (OID: 1.3.6.1.5.5.7.3.3).
    /// </summary>
    [Description("Code Signing")]
    CodeSigning = 8,

    /// <summary>
    /// Email Protection (OID: 1.3.6.1.5.5.7.3.4).
    /// </summary>
    [Description("Email Protection")]
    EmailProtection = 16,

    //IpsecEndSystem= 1.3.6.1.5.5.7.3.5     is deprecated
    //IpsecTunnel   = 1.3.6.1.5.5.7.3.6     is deprecated
    //IpsecUser     = 1.3.6.1.5.5.7.3.7     is deprecated

    /// <summary>
    /// Time Stamping (OID: 1.3.6.1.5.5.7.3.8).
    /// </summary>
    [Description("Time Stamping")]
    TimeStamping = 32,

    /// <summary>
    /// Microsoft Smart Card Logon (OID: 1.3.6.1.4.1.311.20.2.2).
    /// </summary>
    [Description("MS Smart Card Logon")]
    SmartCardLogon = 64,

    /// <summary>
    /// OCSP Signing (OID: 1.3.6.1.5.5.7.3.9).
    /// </summary>
    [Description("OCSP Signing")]
    OcspSigning = 128,

    /// <summary>
    /// Mac Address (vendor-specific OID example 1.3.6.1.1.1.1.22).
    /// </summary>
    [Description("Mac Address")]
    MacAddress = 256,

    /// <summary>
    /// Microsoft EFS (Encrypted File System) certificates (OID: 1.3.6.1.4.1.311.10.3.4).
    /// </summary>
    [Description("MS Encrypted File System (EFS) Certificates")]
    EFS = 512,

    /// <summary>
    /// Microsoft EFS Recovery certificates (OID: 1.3.6.1.4.1.311.10.3.4.1).
    /// </summary>
    [Description("MS EFS Recovery Certificates")]
    EFSRecovery = 1024,

    /// <summary>
    /// SCVP Server (OID: 1.3.6.1.5.5.7.3.15).
    /// </summary>
    [Description("SCVP Server")]
    SCVPServer = 2048,

    /// <summary>
    /// SCVP Client (OID: 1.3.6.1.5.5.7.3.16).
    /// </summary>
    [Description("SCVP Client")]
    SCVPClient = 4096,

    /// <summary>
    /// Internet Key Exchange for IPsec (OID: 1.3.6.1.5.5.7.3.17).
    /// </summary>
    [Description("Internet Key Exchange for IPsec")]
    IPsecIKE = 8192,

    /// <summary>
    /// Internet Key Exchange intermediate for IPsec (OID: 1.3.6.1.5.5.8.2.2).
    /// </summary>
    [Description("Internet Key Exchange intermediate for IPsec")]
    IPsecIKEIntermediate = 16384,

    /// <summary>
    /// Microsoft Key Recovery (OID: 1.3.6.1.4.1.311.10.3.11).
    /// </summary>
    [Description("MS Key Recovery")]
    KeyRecovery = 32768,

    /// <summary>
    /// Microsoft Document Signing (OID: 1.3.6.1.4.1.311.10.3.12).
    /// </summary>
    [Description("MS Document Signing")]
    DocumentSigning = 65536,

    /// <summary>
    /// Intel AMT Management (vendor-specific OID: 2.16.840.1.113741.1.2.3).
    /// </summary>
    [Description("Intel AMT Management")]
    IntelAMTManagement = 131072,

    /// <summary>
    /// Trusted-service Status List (TSL) signing (OID example: 0.4.0.2231.3.0).
    /// </summary>
    [Description("Trusted-service Status List Signing")]
    TSLSigning = 262144,

    /// <summary>
    /// Adobe Authentic Document Trust (OID: 1.2.840.113583.1.1.5).
    /// </summary>
    [Description("Adobe Authentic Document Trust")]
    AdobeAuthenticDocumentTrust = 524288,
}
