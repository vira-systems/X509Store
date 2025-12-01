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

using System.Security.Cryptography;
using System.Text;

namespace Vira.X509Store.Service;

public static partial class Oids
{
    // Symmetric encryption algorithms
    public const string Rc2Cbc        = "1.2.840.113549.3.2";
    public const string Rc4           = "1.2.840.113549.3.4";
    public const string TripleDesCbc  = "1.2.840.113549.3.7";
    public const string DesCbc        = "1.3.14.3.2.7";
    public const string Aes128Cbc     = "2.16.840.1.101.3.4.1.2";
    public const string Aes192Cbc     = "2.16.840.1.101.3.4.1.22";
    public const string Aes256Cbc     = "2.16.840.1.101.3.4.1.42";

    // Asymmetric encryption algorithms
    public const string Dsa                   = "1.2.840.10040.4.1";
    public const string ECDsa                 = "1.2.840.10045.2.1";
    public const string DiffieHellman         = "1.2.840.10046.2.1";
    public const string Rsa                   = "1.2.840.113549.1.1.1";
    public const string RsaOaep               = "1.2.840.113549.1.1.7";
    public const string RsaPss                = "1.2.840.113549.1.1.10";
    public const string RsaPkcs1Md5           = "1.2.840.113549.1.1.4";
    public const string RsaPkcs1Sha1          = "1.2.840.113549.1.1.5";
    public const string RsaPkcs1Sha256        = "1.2.840.113549.1.1.11";
    public const string RsaPkcs1Sha384        = "1.2.840.113549.1.1.12";
    public const string RsaPkcs1Sha512        = "1.2.840.113549.1.1.13";
    public const string RsaPkcs1Sha224        = "1.2.840.113549.1.1.14";
    public const string Esdh                  = "1.2.840.113549.1.9.16.3.5";
    public const string DiffieHellmanPkcs3    = "1.2.840.113549.1.3.1";
    public const string EcDiffieHellman       = "1.3.132.1.12";

    // Cryptographic Attribute Types
    public const string ContentType                   = "1.2.840.113549.1.9.3";
    public const string MessageDigest                 = "1.2.840.113549.1.9.4";
    public const string SigningTime                   = "1.2.840.113549.1.9.5";
    public const string CounterSigner                 = "1.2.840.113549.1.9.6";
    public const string Pkcs9ExtensionRequest         = "1.2.840.113549.1.9.14";
    public const string ContentHint                   = "1.2.840.113549.1.9.16.2.4";
    public const string SigningCertificate            = "1.2.840.113549.1.9.16.2.12";
    public const string BinarySigningTime             = "1.2.840.113549.1.9.16.2.46";
    public const string SigningCertificateV2          = "1.2.840.113549.1.9.16.2.47";
    public const string LocalKeyId                    = "1.2.840.113549.1.9.21";
    public const string CmsAlgorithmProtect           = "1.2.840.113549.1.9.52";
    public const string EnrollCertTypeExtension       = "1.3.6.1.4.1.311.20.2";
    public const string UserPrincipalName             = "1.3.6.1.4.1.311.20.2.3";
    public const string CertificateTemplate           = "1.3.6.1.4.1.311.21.7";
    public const string ApplicationCertPolicies       = "1.3.6.1.4.1.311.21.10";
    public const string DocumentName                  = "1.3.6.1.4.1.311.88.2.1";
    public const string DocumentDescription           = "1.3.6.1.4.1.311.88.2.2";
    //public const string AuthorityInformationAccess    = "1.3.6.1.5.5.7.1.1";
    
    public const string OcspEndpoint                  = "1.3.6.1.5.5.7.48.1";
    public const string CertificateAuthorityIssuers   = "1.3.6.1.5.5.7.48.2";

    public const string OCSPBasicResponse                         = "1.3.6.1.5.5.7.48.1.1";
    public const string OCSPNonceExtension                        = "1.3.6.1.5.5.7.48.1.2";
    public const string OCSPCRL                                   = "1.3.6.1.5.5.7.48.1.3";
    public const string OCSPResponse                              = "1.3.6.1.5.5.7.48.1.4";
    public const string OCSPNoCheckExtension                      = "1.3.6.1.5.5.7.48.1.5";
    public const string OCSPArchiveCutoffExtension                = "1.3.6.1.5.5.7.48.1.6";
    public const string OCSPServiceLocatorExtension               = "1.3.6.1.5.5.7.48.1.7";
    public const string ClientIndicationOfPreferredSignAlgorithms = "1.3.6.1.5.5.7.48.1.8";

    // Key wrap algorithms
    public const string Cms3DesWrap   = "1.2.840.113549.1.9.16.3.6";
    public const string CmsRc2Wrap    = "1.2.840.113549.1.9.16.3.7";

    // PKCS7 Content Types.
    public const string Pkcs7Data             = "1.2.840.113549.1.7.1";
    public const string Pkcs7Signed           = "1.2.840.113549.1.7.2";
    public const string Pkcs7Enveloped        = "1.2.840.113549.1.7.3";
    public const string Pkcs7SignedEnveloped  = "1.2.840.113549.1.7.4";
    public const string Pkcs7Hashed           = "1.2.840.113549.1.7.5";
    public const string Pkcs7Encrypted        = "1.2.840.113549.1.7.6";

    // hash algorithms
    public const string RIPEMD160 = "1.3.36.3.2.1";
    public const string Sha1      = "1.3.14.3.2.26";
    public const string Sha256    = "2.16.840.1.101.3.4.2.1";
    public const string Sha384    = "2.16.840.1.101.3.4.2.2";
    public const string Sha512    = "2.16.840.1.101.3.4.2.3";
    public const string Sha224    = "2.16.840.1.101.3.4.2.4";
    public const string Sha512_224= "2.16.840.1.101.3.4.2.5";
    public const string Sha512_256= "2.16.840.1.101.3.4.2.6";

    // Digest algorithms
    public const string Md2               = "1.2.840.113549.2.2";
    public const string Md4               = "1.2.840.113549.2.3";
    public const string Md5               = "1.2.840.113549.2.5";
    public const string HMacWithSHA1      = "1.2.840.113549.2.7";
    public const string HMacWithSHA224    = "1.2.840.113549.2.8";
    public const string HMacWithSHA256    = "1.2.840.113549.2.9";
    public const string HMacWithSHA384    = "1.2.840.113549.2.10";
    public const string HMacWithSHA512    = "1.2.840.113549.2.11";
    public const string RipeMD160         = "1.3.36.3.2.1";
    public const string RipeMD128         = "1.3.36.3.2.2";
    public const string RipeMD256         = "1.3.36.3.2.3";
    public const string MDC2SLH           = "1.3.36.3.2.4";
    public const string MDC2DLH           = "1.3.36.3.2.5";
    public const string GOST3411Digest    = "1.3.6.1.4.1.5849.1.2.1";

    public const string GOST3411Encrypt   = "1.3.6.1.4.1.5849.1.1.5";
    public const string ECGOST3411Encrypt = "1.3.6.1.4.1.5849.1.6.2";

    // DSA CMS uses the combined signature+digest OID
    public const string DsaWithSha1   = "1.2.840.10040.4.3";
    public const string DsaWithSha224 = "2.16.840.1.101.3.4.3.1";
    public const string DsaWithSha256 = "2.16.840.1.101.3.4.3.2";
    public const string DsaWithSha384 = "2.16.840.1.101.3.4.3.3";
    public const string DsaWithSha512 = "2.16.840.1.101.3.4.3.4";

    // ECDSA CMS uses the combined signature+digest OID
    // https://tools.ietf.org/html/rfc5753#section-2.1.1
    public const string EcPrimeField              = "1.2.840.10045.1.1";
    public const string EcChar2Field              = "1.2.840.10045.1.2";
    public const string EcChar2TrinomialBasis     = "1.2.840.10045.1.2.3.2";
    public const string EcChar2PentanomialBasis   = "1.2.840.10045.1.2.3.3";
    public const string EcPublicKey               = "1.2.840.10045.2.1";
    public const string ECDsaWithSha1             = "1.2.840.10045.4.1";
    public const string ECDsaWithSha224           = "1.2.840.10045.4.3.1";
    public const string ECDsaWithSha256           = "1.2.840.10045.4.3.2";
    public const string ECDsaWithSha384           = "1.2.840.10045.4.3.3";
    public const string ECDsaWithSha512           = "1.2.840.10045.4.3.4";

    public const string Mgf1                      = "1.2.840.113549.1.1.8";
    public const string PSpecified                = "1.2.840.113549.1.1.9";

    // PKCS#7
    public const string NoSignature   = "1.3.6.1.5.5.7.6.2";

    //Standard Curve (brainpool & nist)
    public const string brainpoolP160r1   = "1.3.36.3.3.2.8.1.1.1";
    public const string brainpoolP160t1   = "1.3.36.3.3.2.8.1.1.2";
    public const string brainpoolP192r1   = "1.3.36.3.3.2.8.1.1.3";
    public const string brainpoolP192t1   = "1.3.36.3.3.2.8.1.1.4";
    public const string brainpoolP224r1   = "1.3.36.3.3.2.8.1.1.5";
    public const string brainpoolP224t1   = "1.3.36.3.3.2.8.1.1.6";
    public const string brainpoolP256r1   = "1.3.36.3.3.2.8.1.1.7";
    public const string brainpoolP256t1   = "1.3.36.3.3.2.8.1.1.8";
    public const string brainpoolP320r1   = "1.3.36.3.3.2.8.1.1.9";
    public const string brainpoolP320t1   = "1.3.36.3.3.2.8.1.1.10";
    public const string brainpoolP384r1   = "1.3.36.3.3.2.8.1.1.11";
    public const string brainpoolP384t1   = "1.3.36.3.3.2.8.1.1.12";
    public const string brainpoolP512r1   = "1.3.36.3.3.2.8.1.1.13";
    public const string brainpoolP512t1   = "1.3.36.3.3.2.8.1.1.14";
    public const string nistP192          = "1.2.840.10045.3.1.1"; //not supported by microsoft
    public const string nistP256          = "1.2.840.10045.3.1.7";
    public const string nistP224          = "1.3.132.0.33"; //not supported by microsoft
    public const string nistP384          = "1.3.132.0.34";
    public const string nistP521          = "1.3.132.0.35";

    // Cert Extensions
    public const string SubjectDirectoryAttributes= "2.5.29.9";
    public const string BasicConstraints          = "2.5.29.10";
    public const string SubjectKeyIdentifier      = "2.5.29.14";
    public const string KeyUsage                  = "2.5.29.15";
    public const string SubjectAltName            = "2.5.29.17";
    public const string IssuerAltName             = "2.5.29.18";
    public const string BasicConstraints2         = "2.5.29.19";
    public const string CrlNumber                 = "2.5.29.20";
    public const string CrlReasons                = "2.5.29.21";
    public const string ReasonCode                = "2.5.29.21";
    public const string InstructionCode           = "2.5.29.23";
    public const string InvalidityDate            = "2.5.29.24";
    public const string DeltaCrlIndicator         = "2.5.29.27";
    public const string IssuingDistributionPoint  = "2.5.29.28";
    public const string CertificateIssuer         = "2.5.29.29";
    public const string NameConstraints           = "2.5.29.30";
    public const string CrlDistributionPoints     = "2.5.29.31";
    public const string CertPolicies              = "2.5.29.32";
    public const string AnyCertPolicy             = "2.5.29.32.0";
    public const string CertPolicyMappings        = "2.5.29.33";
    public const string AuthorityKeyIdentifier    = "2.5.29.35";
    public const string CertPolicyConstraints     = "2.5.29.36";
    public const string EnhancedKeyUsage          = "2.5.29.37";
    public const string FreshestCrl               = "2.5.29.46";
    public const string InhibitAnyPolicy          = "2.5.29.54";
    public const string AuthorityInformationAccess= "1.3.6.1.5.5.7.1.1";
    public const string SubjectInfoAccess         = "1.3.6.1.5.5.7.1.11";
    public const string LogoType                  = "1.3.6.1.5.5.7.1.12";
    public const string BiometricInfo             = "1.3.6.1.5.5.7.1.2";
    public const string QCStatements              = "1.3.6.1.5.5.7.1.3";
    public const string AuditIdentity             = "1.3.6.1.5.5.7.1.4";
    public const string InhibitAnyPolicyExtension = "2.5.29.54";
    public const string TargetInformation         = "2.5.29.55";
    public const string NoRevAvail                = "2.5.29.56";
    public const string ExpiredCertsOnCrl         = "2.5.29.60";

    // RFC3161 Timestamping
    public const string TimeStampingInfo          = "1.2.840.113549.1.9.16.1.4";
    public const string TimeStampToken            = "1.2.840.113549.1.9.16.2.14";
    public const string ContentTimeStamp          = "1.2.840.113549.1.9.16.2.20";
    public const string EscTimeStamp              = "1.2.840.113549.1.9.16.2.25";
    public const string CertCRLTimestamp          = "1.2.840.113549.1.9.16.2.26";
    public const string ArchiveTimeStamp          = "1.2.840.113549.1.9.16.2.27";
    //public const string BinarySigningTime         = "1.2.840.113549.1.9.16.2.46";
    public const string ArchiveTimestampV2        = "1.2.840.113549.1.9.16.2.48";
    public const string TimeStampingPolicy        = "1.3.6.1.4.1.13762.3";
    public const string TimeStampingPurpose       = "1.3.6.1.5.5.7.3.8";

    // PKCS#12
    private const string Pkcs12Prefix                   = "1.2.840.113549.1.12.";
    private const string Pkcs12PbePrefix                = Pkcs12Prefix + "1.";
    public const string Pkcs12PbeWithShaAnd3Key3Des     = Pkcs12PbePrefix + "3";
    public const string Pkcs12PbeWithShaAnd2Key3Des     = Pkcs12PbePrefix + "4";
    public const string Pkcs12PbeWithShaAnd128BitRC2    = Pkcs12PbePrefix + "5";
    public const string Pkcs12PbeWithShaAnd40BitRC2     = Pkcs12PbePrefix + "6";
    private const string Pkcs12BagTypesPrefix           = Pkcs12Prefix + "10.1.";
    public const string Pkcs12KeyBag                    = Pkcs12BagTypesPrefix + "1";
    public const string Pkcs12ShroudedKeyBag            = Pkcs12BagTypesPrefix + "2";
    public const string Pkcs12CertBag                   = Pkcs12BagTypesPrefix + "3";
    public const string Pkcs12CrlBag                    = Pkcs12BagTypesPrefix + "4";
    public const string Pkcs12SecretBag                 = Pkcs12BagTypesPrefix + "5";
    public const string Pkcs12SafeContentsBag           = Pkcs12BagTypesPrefix + "6";
    public const string Pkcs12X509CertBagType           = "1.2.840.113549.1.9.22.1";
    public const string Pkcs12SdsiCertBagType           = "1.2.840.113549.1.9.22.2";

    // PKCS#5
    private const string Pkcs5Prefix                        = "1.2.840.113549.1.5.";
    public const string PbeWithMD5AndDESCBC               = Pkcs5Prefix + "3";
    public const string PbeWithMD5AndRC2CBC               = Pkcs5Prefix + "6";
    public const string PbeWithSha1AndDESCBC              = Pkcs5Prefix + "10";
    public const string PbeWithSha1AndRC2CBC              = Pkcs5Prefix + "11";
    public const string Pbkdf2                            = Pkcs5Prefix + "12";
    public const string PasswordBasedEncryptionScheme2    = Pkcs5Prefix + "13";

    private const string RsaDsiDigestAlgorithmPrefix    = "1.2.840.113549.2.";
    public const string HmacWithSha1                    = RsaDsiDigestAlgorithmPrefix + "7";
    public const string HmacWithSha256                  = RsaDsiDigestAlgorithmPrefix + "9";
    public const string HmacWithSha384                  = RsaDsiDigestAlgorithmPrefix + "10";
    public const string HmacWithSha512                  = RsaDsiDigestAlgorithmPrefix + "11";

    // Elliptic Curve curve identifiers
    public const string SECP256r1 = "1.2.840.10045.3.1.7";
    public const string SECP384r1 = "1.3.132.0.34";
    public const string SECP521r1 = "1.3.132.0.35";

    // Extended Key Usage
    public const string KeyPurposeTSLSigning                  = "0.4.0.2231.3.0";
    public const string KeyPurposeAdobeAuthenticDocumentTrust = "1.2.840.113583.1.1.5";
    public const string KeyPurposeMacAddress                  = "1.3.6.1.1.1.1.22";
    public const string KeyPurposeServerAuthentication        = "1.3.6.1.5.5.7.3.1";
    public const string KeyPurposeClientAuthentication        = "1.3.6.1.5.5.7.3.2";
    public const string KeyPurposeCodeSigning                 = "1.3.6.1.5.5.7.3.3";
    public const string KeyPurposeEmailProtection             = "1.3.6.1.5.5.7.3.4";
    public const string KeyPurposeIpsecEndSystem              = "1.3.6.1.5.5.7.3.5";
    public const string KeyPurposeIpsecTunnel                 = "1.3.6.1.5.5.7.3.6";
    public const string KeyPurposeIpsecUser                   = "1.3.6.1.5.5.7.3.7";
    public const string KeyPurposeTimeStamping                = "1.3.6.1.5.5.7.3.8";
    public const string KeyPurposeOcspSigning                 = "1.3.6.1.5.5.7.3.9";
    public const string KeyPurposeSCVPServer                  = "1.3.6.1.5.5.7.3.15";
    public const string KeyPurposeSCVPClient                  = "1.3.6.1.5.5.7.3.16";
    public const string KeyPurposeIPsecIKE                    = "1.3.6.1.5.5.7.3.17";
    public const string KeyPurposeIPsecIKEIntermediate        = "1.3.6.1.5.5.8.2.2";
    public const string KeyPurposeEncryptedFileSystem         = "1.3.6.1.4.1.311.10.3.4";
    public const string KeyPurposeEncryptedFileSystemRecovery = "1.3.6.1.4.1.311.10.3.4.1";
    public const string KeyPurposeKeyRecovery                 = "1.3.6.1.4.1.311.10.3.11";
    public const string KeyPurposeDocumentSigning             = "1.3.6.1.4.1.311.10.3.12";
    public const string KeyPurposeSmartCardLogon              = "1.3.6.1.4.1.311.20.2.2";
    public const string KeyPurposeAnyExtendedKeyUsage         = "2.5.29.37.0";
    public const string KeyPurposeIntelAMTManagement          = "2.16.840.1.113741.1.2.3";
    //Authentic Documents Trust: Indicates that the particular credential can be used for the Certified Document Services (CDS).
    //{iso(1) member-body(2) us(840) adbe(113583) acrobat(1) security(1) 5}
    public const string KeyPurposeCertifiedDocumentServices   = "1.2.840.113583.1.1.5";

    // X500 Names
    public const string CommonName            = "2.5.4.3";    /* CN, UTF8String, Multiple */
    public const string Surname               = "2.5.4.4";    /* SN | SURNAME, UTF8String, Multiple */
    public const string SerialNumber          = "2.5.4.5";    /* SERIALNUMBER, PrintableString, Single */
    public const string Country               = "2.5.4.6";    /* C, PrintableString, Single */
    public const string Locality              = "2.5.4.7";    /* L, UTF8String, Single */
    public const string StateOrProvince       = "2.5.4.8";    /* ST | S, UTF8String, Single */
    public const string StreetAddress         = "2.5.4.9";    /* STREET, UTF8String, Multiple */
    public const string Organization          = "2.5.4.10";   /* O, UTF8String, Single */
    public const string OrganizationalUnit    = "2.5.4.11";   /* OU, UTF8String, Multiple */
    public const string JobTitle              = "2.5.4.12";   /* T | TITLE, UTF8String, Multiple */
    public const string Description           = "2.5.4.13";   /* DESCRIPTION, UTF8String, Multiple */
    public const string BusinessCategory      = "2.5.4.15";   /* BUSINESSCATEGORY, UTF8String */
    public const string PostalAddress         = "2.5.4.16";   /* POSTALADDRESS, UTF8String, Single */
    public const string PostalCode            = "2.5.4.17";   /* POSTALCODE, UTF8String, Single */
    public const string TelephoneNumber       = "2.5.4.20";   /* PHONE, PrintableString */
    public const string Name                  = "2.5.4.41";   /* NAME, UTF8String */
    public const string GivenName             = "2.5.4.42";   /* GIVENNAME | G | GN, UTF8String, Multiple */
    public const string Initials              = "2.5.4.43";   /* INITIALS, UTF8String */
    public const string GenerationQualifier   = "2.5.4.44";   /* GENERATION | generationQualifier, UTF8String */
    public const string UniqueIdentifier      = "2.5.4.45";   /* UID, HEX value encode in UTF8String, Single */
    public const string DomainNameQualifier   = "2.5.4.46";   /* DN | dnQualifier, PrintableString, Single */
    public const string DmdName               = "2.5.4.54";   /* DMD, UTF8String */
    public const string Pseudonym             = "2.5.4.65";   /* pseudonym, UTF8String, Single */
    public const string OrganizationIdentifier= "2.5.4.97";   /* ORGANIZATIONIDENTIFIER, PrintableString, Single */    
    public const string NameAtBirth           = "1.3.36.8.3.14";              /* NAMEATBIRTH, UTF8String */
    public const string EmailAddress          = "1.2.840.113549.1.9.1";       /* E | MAIL, IA5String, Single */
    public const string UnstructuredName      = "1.2.840.113549.1.9.2";       /* UNSTRUCTUREDNAME, UTF8String, Multiple */
    public const string UnstructuredAddress   = "1.2.840.113549.1.9.8";       /* UNSTRUCTUREDADDRESS, UTF8String, Multiple */
    public const string UserIdentifier        = "0.9.2342.19200300.100.1.1";  /* UID, UTF8String, Single */
    public const string DomainComponent       = "0.9.2342.19200300.100.1.25"; /* DC, IA5String, Multiple */

    // X500 Alternative Names                           = "2.5.29.17"
    public const string DirectoryName                 = "0.2.262.1.10.7.30";
    //public const string OtherName                   = "";
    public const string RFC822Name                    = "1.3.6.1.2.1.198.1.1.2";
    //public const string DnsName                     = "1.3.6.1.2.1.32";
    //public const string IpAddress                   = "";
    public const string X400Address                   = "1.3.6.1.5.5.7.0.60";
    //public const string EdiPartyName                = "";
    //public const string URI                         = "";
    //public const string RegisteredID                = "";
    public const string UPN                           = "1.3.6.1.4.1.311.20.2.3";
    //public const string GUID                        = "";
    //public const string KRB5PrincipalName           = "";
    //public const string ServiceName                 = "";
    //public const string SubjectIdentificationMethod = "";
    public const string PermanentIdentifier           = "1.3.6.1.5.5.7.8.3";
    public const string XMPPADDR                      = "1.3.6.1.5.5.7.8.5";

    // x500 Directory
    public const string DateOfBirth             = "1.3.6.1.5.5.7.9.1"; // GeneralizedTime
    public const string PlaceOfBirth            = "1.3.6.1.5.5.7.9.2"; // UTF8String
    public const string Gender                  = "1.3.6.1.5.5.7.9.3"; // PrintableString
    public const string CountryOfCitizenship    = "1.3.6.1.5.5.7.9.4"; // PrintableString
    public const string CountryOfResidence      = "1.3.6.1.5.5.7.9.5"; // PrintableString



    // Symmetric encryption algorithms
    private static volatile Oid? _rc2CbcOid;
    private static volatile Oid? _rc4Oid;
    private static volatile Oid? _tripleDesCbcOid;
    private static volatile Oid? _desCbcOid;
    private static volatile Oid? _aes128CbcOid;
    private static volatile Oid? _aes192CbcOid;
    private static volatile Oid? _aes256CbcOid;


    private static volatile Oid? _md5Oid;

    private static volatile Oid? _sha1Oid;

    private static volatile Oid? _sha224Oid;

    private static volatile Oid? _sha256Oid;

    private static volatile Oid? _sha384Oid;

    private static volatile Oid? _sha512Oid;

    private static volatile Oid? _ripemd160Oid;

    private static volatile Oid? _rsaOid;

    private static volatile Oid? _ecPublicKeyOid;

    private static volatile Oid? _secp256r1Oid;

    private static volatile Oid? _secp384r1Oid;

    private static volatile Oid? _secp521r1Oid;

    private static volatile Oid? _pkcs7DataOid;

    private static volatile Oid? _contentTypeOid;

    private static volatile Oid? _documentDescriptionOid;

    private static volatile Oid? _documentNameOid;

    private static volatile Oid? _localKeyIdOid;

    private static volatile Oid? _messageDigestOid;

    private static volatile Oid? _signingTimeOid;

    private static volatile Oid? _pkcs9ExtensionRequestOid;

    private static volatile Oid? _timeStampingPolicyOid;

    private static volatile Oid? _subjectDirectoryAttributesOid;
    private static volatile Oid? _basicConstraintsOid;
    private static volatile Oid? _subjectKeyIdentifierOid;
    private static volatile Oid? _keyUsageOid;
    private static volatile Oid? _subjectAltNameOid;
    private static volatile Oid? _issuerAltNameOid;
    private static volatile Oid? _basicConstraints2Oid;
    private static volatile Oid? _crlNumberOid;
    private static volatile Oid? _reasonCodeOid;
    private static volatile Oid? _instructionCodeOid;
    private static volatile Oid? _invalidityDateOid;
    private static volatile Oid? _deltaCrlIndicatorOid;
    private static volatile Oid? _issuingDistributionPointOid;
    private static volatile Oid? _certificateIssuerOid;
    private static volatile Oid? _nameConstraintsOid;
    private static volatile Oid? _crlDistributionPointsOid;
    private static volatile Oid? _certPoliciesOid;
    private static volatile Oid? _anyCertPolicyOid;
    private static volatile Oid? _certPolicyMappingsOid;
    private static volatile Oid? _authorityKeyIdentifierOid;
    private static volatile Oid? _certPolicyConstraintsOid;
    private static volatile Oid? _enhancedKeyUsageOid;
    private static volatile Oid? _freshestCrlOid;
    private static volatile Oid? _inhibitAnyPolicyOid;
    private static volatile Oid? _authorityInformationAccessOid;
    private static volatile Oid? _subjectInfoAccessOid;
    private static volatile Oid? _logoTypeOid;
    private static volatile Oid? _biometricInfoOid;
    private static volatile Oid? _qcStatementsOid;
    private static volatile Oid? _auditIdentityOid;
    private static volatile Oid? _noRevAvailOid;
    private static volatile Oid? _targetInformationOid;
    private static volatile Oid? _expiredCertsOnCrlOid;

    internal static Oid Aes128CbcOid => _aes128CbcOid ??= InitializeOid(Aes128Cbc);
    internal static Oid Aes192CbcOid => _aes192CbcOid ??= InitializeOid(Aes192Cbc);
    internal static Oid Aes256CbcOid => _aes256CbcOid ??= InitializeOid(Aes256Cbc);
    internal static Oid DesCbcOid => _desCbcOid ??= InitializeOid(DesCbc);
    internal static Oid Rc2CbcOid => _rc2CbcOid ??= InitializeOid(Rc2Cbc);
    internal static Oid Rc4Oid => _rc4Oid ??= InitializeOid(Rc4);
    internal static Oid TripleDesCbcOid => _tripleDesCbcOid ??= InitializeOid(TripleDesCbc);

    internal static Oid RsaOid => _rsaOid ??= InitializeOid(Rsa);

    internal static Oid EcPublicKeyOid => _ecPublicKeyOid ??= InitializeOid(EcPublicKey);

    internal static Oid SECP256r1Oid => _secp256r1Oid ??= new Oid(SECP256r1, "nistP256");

    internal static Oid SECP384r1Oid => _secp384r1Oid ??= new Oid(SECP384r1, "nistP384");

    internal static Oid SECP521r1Oid => _secp521r1Oid ??= new Oid(SECP521r1, "nistP521");

    internal static Oid MD5Oid => _md5Oid ??= InitializeOid(Md5);

    internal static Oid Sha1Oid => _sha1Oid ??= InitializeOid(Sha1);

    internal static Oid Sha224Oid => _sha224Oid ??= InitializeOid(Sha224);

    internal static Oid Sha256Oid => _sha256Oid ??= InitializeOid(Sha256);

    internal static Oid Sha384Oid => _sha384Oid ??= InitializeOid(Sha384);

    internal static Oid Sha512Oid => _sha512Oid ??= InitializeOid(Sha512);

    internal static Oid RIPEMD160Oid => _ripemd160Oid ??= InitializeOid(RIPEMD160);

    internal static Oid Pkcs7DataOid => _pkcs7DataOid ??= InitializeOid(Pkcs7Data);

    internal static Oid ContentTypeOid => _contentTypeOid ??= InitializeOid(ContentType);

    internal static Oid DocumentDescriptionOid => _documentDescriptionOid ??= InitializeOid(DocumentDescription);

    internal static Oid DocumentNameOid => _documentNameOid ??= InitializeOid(DocumentName);

    internal static Oid LocalKeyIdOid => _localKeyIdOid ??= InitializeOid(LocalKeyId);

    internal static Oid MessageDigestOid => _messageDigestOid ??= InitializeOid(MessageDigest);

    internal static Oid SigningTimeOid => _signingTimeOid ??= InitializeOid(SigningTime);

    internal static Oid Pkcs9ExtensionRequestOid => _pkcs9ExtensionRequestOid ??= InitializeOid(Pkcs9ExtensionRequest);

    internal static Oid TimeStampingPolicyOid => _timeStampingPolicyOid ??= InitializeOid(TimeStampingPolicy);

    internal static Oid SubjectDirectoryAttributesOid => _subjectDirectoryAttributesOid ??= InitializeOid(SubjectDirectoryAttributes);
    internal static Oid BasicConstraintsOid => _basicConstraintsOid ??= InitializeOid(BasicConstraints);
    internal static Oid SubjectKeyIdentifierOid => _subjectKeyIdentifierOid ??= InitializeOid(SubjectKeyIdentifier);
    internal static Oid KeyUsageOid => _keyUsageOid ??= InitializeOid(KeyUsage);
    internal static Oid SubjectAltNameOid => _subjectAltNameOid ??= InitializeOid(SubjectAltName);
    internal static Oid IssuerAltNameOid => _issuerAltNameOid ??= InitializeOid(IssuerAltName);
    internal static Oid BasicConstraints2Oid => _basicConstraints2Oid ??= InitializeOid(BasicConstraints2);
    internal static Oid CrlNumberOid => _crlNumberOid ??= InitializeOid(CrlNumber);
    internal static Oid ReasonCodeOid => _reasonCodeOid ??= InitializeOid(ReasonCode);
    internal static Oid InstructionCodeOid => _instructionCodeOid ??= InitializeOid(InstructionCode);
    internal static Oid InvalidityDateOid => _invalidityDateOid ??= InitializeOid(InvalidityDate);
    internal static Oid DeltaCrlIndicatorOid => _deltaCrlIndicatorOid ??= InitializeOid(DeltaCrlIndicator);
    internal static Oid IssuingDistributionPointOid => _issuingDistributionPointOid ??= InitializeOid(IssuingDistributionPoint);
    internal static Oid CertificateIssuerOid => _certificateIssuerOid ??= InitializeOid(CertificateIssuer);
    internal static Oid NameConstraintsOid => _nameConstraintsOid ??= InitializeOid(NameConstraints);
    internal static Oid CrlDistributionPointsOid => _crlDistributionPointsOid ??= InitializeOid(CrlDistributionPoints);
    internal static Oid CertPoliciesOid => _certPoliciesOid ??= InitializeOid(CertPolicies);
    internal static Oid AnyCertPolicyOid => _anyCertPolicyOid ??= InitializeOid(AnyCertPolicy);
    internal static Oid CertPolicyMappingsOid => _certPolicyMappingsOid ??= InitializeOid(CertPolicyMappings);
    internal static Oid AuthorityKeyIdentifierOid => _authorityKeyIdentifierOid ??= InitializeOid(AuthorityKeyIdentifier);
    internal static Oid CertPolicyConstraintsOid => _certPolicyConstraintsOid ??= InitializeOid(CertPolicyConstraints);
    internal static Oid EnhancedKeyUsageOid => _enhancedKeyUsageOid ??= InitializeOid(EnhancedKeyUsage);
    internal static Oid FreshestCrlOid => _freshestCrlOid ??= InitializeOid(FreshestCrl);
    internal static Oid InhibitAnyPolicyOid => _inhibitAnyPolicyOid ??= InitializeOid(InhibitAnyPolicy);
    internal static Oid AuthorityInformationAccessOid => _authorityInformationAccessOid ??= InitializeOid(AuthorityInformationAccess);
    internal static Oid SubjectInfoAccessOid => _subjectInfoAccessOid ??= InitializeOid(SubjectInfoAccess);
    internal static Oid LogoTypeOid => _logoTypeOid ??= InitializeOid(LogoType);
    internal static Oid BiometricInfoOid => _biometricInfoOid ??= InitializeOid(BiometricInfo);
    internal static Oid QCStatementsOid => _qcStatementsOid ??= InitializeOid(QCStatements);
    internal static Oid AuditIdentityOid => _auditIdentityOid ??= InitializeOid(AuditIdentity);
    internal static Oid NoRevAvailOid => _noRevAvailOid ??= InitializeOid(NoRevAvail);
    internal static Oid TargetInformationOid => _targetInformationOid ??= InitializeOid(TargetInformation);
    internal static Oid ExpiredCertsOnCrlOid => _expiredCertsOnCrlOid ??= InitializeOid(ExpiredCertsOnCrl);

    internal static string FromArray(byte[] oid)
    {
        var sb = new StringBuilder();

        for (int i = 0; i < oid.Length; i++)
        {
            if (i == 0)
            {
                int b = oid[0] % 40;
                int a = (oid[0] - b) / 40;
                sb.AppendFormat("{0}.{1}", a, b);
            }
            else
            {
                if (oid[i] < 128)
                    sb.AppendFormat(".{0}", oid[i]);
                else
                {
                    sb.AppendFormat(".{0}", (oid[i] - 128) * 128 + oid[i + 1]);
                    i++;
                }
            }
        }

        return sb.ToString();
    }

    internal static byte[] ToArray(string oid)
    {
        var parts = oid.Trim(' ', '.').Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var oids = new List<int>();

        for (int a = 0, i = 0; i < parts.Length; i++)
        {
            switch (i)
            {
                case 0:
                    a = int.Parse(parts[0]);
                    break;
                case 1:
                    oids.Add(40 * a + int.Parse(parts[1]));
                    break;
                default:
                    int b = int.Parse(parts[i]);
                    if (b < 128)
                    {
                        oids.Add(b);
                    }
                    else
                    {
                        oids.Add(128 + b / 128);
                        oids.Add(b % 128);
                    }
                    break;
            }
        }

        return [.. oids.Select(i => Convert.ToByte(i))];
    }

    private static Oid InitializeOid(string value)
    {
        var oid = new Oid(value, null);
        _ = oid.FriendlyName;
        return oid;
    }
}
