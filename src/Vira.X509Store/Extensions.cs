using Net.Pkcs11Interop.Common;
using Org.BouncyCastle.Asn1;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Vira.X509Store.Pkcs11;
using BcX509 = Org.BouncyCastle.Asn1.X509;

namespace Vira.X509Store;

/// <summary>
/// Collection of extension methods used throughout the X509 store service.
/// Includes helpers for algorithm mapping, RSA padding selection, secure string
/// conversion, X509 conversions and PKCS#11 exception handling.
/// </summary>
public static class Extensions
{
    #region Algorithm Extensions

    /// <summary>
    /// Maps a service <see cref="EncryptionAlgorithm"/> value to a BouncyCastle
    /// <see cref="AlgorithmIdentifier"/> representing the corresponding OID.
    /// </summary>
    /// <param name="algorithm">The symmetric encryption algorithm enum value.</param>
    /// <returns>An <see cref="AlgorithmIdentifier"/> for the requested algorithm.</returns>
    /// <exception cref="NotSupportedException">Thrown when an unsupported algorithm is provided.</exception>
    public static AlgorithmIdentifier ToAlgorithmIdentifier(this EncryptionAlgorithm algorithm)
    {
        return algorithm switch
        {
            EncryptionAlgorithm.RC2 => new AlgorithmIdentifier(Oids.Rc2CbcOid),
            EncryptionAlgorithm.RC4 => new AlgorithmIdentifier(Oids.Rc4Oid),
            EncryptionAlgorithm.TripleDES => new AlgorithmIdentifier(Oids.TripleDesCbcOid),
            EncryptionAlgorithm.DES => new AlgorithmIdentifier(Oids.DesCbcOid),
            EncryptionAlgorithm.AES128 => new AlgorithmIdentifier(Oids.Aes128CbcOid),
            EncryptionAlgorithm.AES192 => new AlgorithmIdentifier(Oids.Aes192CbcOid),
            EncryptionAlgorithm.AES256 => new AlgorithmIdentifier(Oids.Aes256CbcOid),
            _ => throw new NotSupportedException(),
        };
    }

    /// <summary>
    /// Converts a <see cref="HashAlgorithmFlags"/> enum value to the .NET
    /// <see cref="HashAlgorithmName"/> equivalent used for cryptographic operations.
    /// </summary>
    /// <param name="algorithm">Hash algorithm enum value.</param>
    /// <returns>Corresponding <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="NotSupportedException">Thrown if the algorithm is not supported.</exception>
    public static HashAlgorithmName ToHashAlgorithmName(this HashAlgorithmFlags algorithm)
    {
        return algorithm switch
        {
            HashAlgorithmFlags.MD5 => HashAlgorithmName.MD5,
            HashAlgorithmFlags.SHA1 => HashAlgorithmName.SHA1,
            HashAlgorithmFlags.SHA256 => HashAlgorithmName.SHA256,
            HashAlgorithmFlags.SHA384 => HashAlgorithmName.SHA384,
            HashAlgorithmFlags.SHA512 => HashAlgorithmName.SHA512,
            HashAlgorithmFlags.SHA3_256 => HashAlgorithmName.SHA3_256,
            HashAlgorithmFlags.SHA3_384 => HashAlgorithmName.SHA3_384,
            HashAlgorithmFlags.SHA3_512 => HashAlgorithmName.SHA3_512,
            _ => throw new NotSupportedException(),
        };
    }

    #endregion

    #region RSA Padding Extensions

    /// <summary>
    /// Converts the service <see cref="RSAEncryptionPaddingMode"/> and optional
    /// <see cref="HashAlgorithmFlags"/> into a concrete <see cref="RSAEncryptionPadding"/> instance.
    /// </summary>
    /// <param name="mode">Requested RSA encryption padding mode.</param>
    /// <param name="hashAlgorithm">Hash algorithm used for OAEP modes (defaults to SHA256).</param>
    /// <returns>A configured <see cref="RSAEncryptionPadding"/>.</returns>
    public static RSAEncryptionPadding ToRSAEncryptionPadding(this RSAEncryptionPaddingMode mode, HashAlgorithmFlags hashAlgorithm = HashAlgorithmFlags.SHA256)
    {
        if (mode == RSAEncryptionPaddingMode.Pkcs1)
            return RSAEncryptionPadding.Pkcs1;

        return hashAlgorithm switch
        {
            HashAlgorithmFlags.SHA1 => RSAEncryptionPadding.OaepSHA1,
            HashAlgorithmFlags.SHA256 => RSAEncryptionPadding.OaepSHA256,
            HashAlgorithmFlags.SHA384 => RSAEncryptionPadding.OaepSHA384,
            HashAlgorithmFlags.SHA512 => RSAEncryptionPadding.OaepSHA512,
            HashAlgorithmFlags.SHA3_256 => RSAEncryptionPadding.OaepSHA3_256,
            HashAlgorithmFlags.SHA3_384 => RSAEncryptionPadding.OaepSHA3_384,
            HashAlgorithmFlags.SHA3_512 => RSAEncryptionPadding.OaepSHA3_512,
            _ => RSAEncryptionPadding.OaepSHA256,
            //throw new NotSupportedException(),
        };
    }

    /// <summary>
    /// Converts nullable service <see cref="RSASignaturePaddingMode"/> to
    /// a concrete <see cref="RSASignaturePadding"/> instance. Null or PKCS#1
    /// returns <see cref="RSASignaturePadding.Pkcs1"/>, otherwise PSS is returned.
    /// </summary>
    /// <param name="mode">Nullable signature padding mode.</param>
    /// <returns>Resolved <see cref="RSASignaturePadding"/>.</returns>
    public static RSASignaturePadding ToRSASignaturePadding(this RSASignaturePaddingMode? mode)
    {
        if (mode == null || mode == RSASignaturePaddingMode.Pkcs1)
            return RSASignaturePadding.Pkcs1;
        else
            return RSASignaturePadding.Pss;
    }

    #endregion

    #region Secure String Extensions

    /// <summary>
    /// Creates a <see cref="SecureString"/> from a UTF-8 encoded byte array.
    /// </summary>
    /// <param name="values">Byte array containing UTF-8 encoded characters.</param>
    /// <returns>A <see cref="SecureString"/> containing the decoded characters.</returns>
    public static SecureString ToSecureString(this byte[] values)
    {
        var secureStr = new SecureString();
        foreach (var item in Encoding.UTF8.GetString(values))
        {
            secureStr.AppendChar(item);
        }
        return secureStr;
    }

    /// <summary>
    /// Creates a <see cref="SecureString"/> from a char array.
    /// </summary>
    /// <param name="values">Character array to copy into the secure string.</param>
    /// <returns>A <see cref="SecureString"/> containing the provided characters.</returns>
    public static SecureString ToSecureString(this char[] values)
    {
        var secureStr = new SecureString();
        foreach (var item in values)
        {
            secureStr.AppendChar(item);
        }
        return secureStr;
    }

    /// <summary>
    /// Creates a <see cref="SecureString"/> from a managed string.
    /// </summary>
    /// <param name="value">The input string to convert.</param>
    /// <returns>A <see cref="SecureString"/> with the same characters.</returns>
    public static SecureString ToSecureString(this string value)
    {
        var secureStr = new SecureString();
        foreach (var item in value)
        {
            secureStr.AppendChar(item);
        }
        return secureStr;
    }

    /// <summary>
    /// Converts a <see cref="SecureString"/> into a plain text string.
    /// </summary>
    /// <param name="value">SecureString instance to convert.</param>
    /// <returns>Plain text string representation of the secure string.</returns>
    public static string ToPlainString(this SecureString value)
    {
        nint bstr = nint.Zero;

        try
        {
            bstr = Marshal.SecureStringToBSTR(value);
            return Marshal.PtrToStringBSTR(bstr);
        }
        finally
        {
            if (bstr != nint.Zero)
            {
                Marshal.ZeroFreeBSTR(bstr);
            }
        }
    }

    /// <summary>
    /// Converts a <see cref="SecureString"/> to a UTF-8 encoded byte array.
    /// </summary>
    /// <param name="value">SecureString to convert.</param>
    /// <returns>UTF-8 byte array representing the secure string contents.</returns>
    public static byte[] ToByteArray(this SecureString value)
    {
        var bstr = value.ToPlainString();
        return Encoding.UTF8.GetBytes(bstr);
    }

    #endregion

    #region Signature Algorithm Extensions

    /// <summary>
    /// Maps a <see cref="SignatureAlgorithms"/> enum to the corresponding PKCS#11
    /// mechanism type (<see cref="CKM"/>).
    /// </summary>
    /// <param name="algorithm">Signature algorithm enum value.</param>
    /// <returns>PKCS#11 mechanism representing the signature operation.</returns>
    /// <exception cref="NotSupportedException">Thrown when the algorithm is not supported.</exception>
    public static CKM ToMechanism(this SignatureAlgorithms algorithm)
    {
        return algorithm switch
        {
            SignatureAlgorithms.SHA1WithRSA => CKM.CKM_SHA1_RSA_PKCS,
            SignatureAlgorithms.SHA256WithRSA => CKM.CKM_SHA256_RSA_PKCS,
            SignatureAlgorithms.SHA384WithRSA => CKM.CKM_SHA384_RSA_PKCS,
            SignatureAlgorithms.SHA512WithRSA => CKM.CKM_SHA512_RSA_PKCS,
            SignatureAlgorithms.SHA1WithECDSA => CKM.CKM_ECDSA_SHA1,
            SignatureAlgorithms.SHA224WithECDSA => CKM.CKM_ECDSA_SHA224,
            SignatureAlgorithms.SHA256WithECDSA => CKM.CKM_ECDSA_SHA256,
            SignatureAlgorithms.SHA384WithECDSA => CKM.CKM_ECDSA_SHA384,
            SignatureAlgorithms.SHA512WithECDSA => CKM.CKM_ECDSA_SHA512,
            _ => throw new NotSupportedException(),
        };
    }

    /// <summary>
    /// Returns the OID string associated with a <see cref="SignatureAlgorithms"/> value.
    /// </summary>
    /// <param name="algorithm">Signature algorithm enum value.</param>
    /// <returns>OID string for the signature algorithm.</returns>
    public static string ToOid(this SignatureAlgorithms algorithm)
    {
        return algorithm switch
        {
            SignatureAlgorithms.SHA1WithRSA => Oids.RsaPkcs1Sha1,
            SignatureAlgorithms.SHA256WithRSA => Oids.RsaPkcs1Sha256,
            SignatureAlgorithms.SHA384WithRSA => Oids.RsaPkcs1Sha384,
            SignatureAlgorithms.SHA512WithRSA => Oids.RsaPkcs1Sha512,
            SignatureAlgorithms.SHA1WithECDSA => Oids.ECDsaWithSha1,
            SignatureAlgorithms.SHA224WithECDSA => Oids.ECDsaWithSha224,
            SignatureAlgorithms.SHA256WithECDSA => Oids.ECDsaWithSha256,
            SignatureAlgorithms.SHA384WithECDSA => Oids.ECDsaWithSha384,
            SignatureAlgorithms.SHA512WithECDSA => Oids.ECDsaWithSha512,
            _ => throw new NotSupportedException(),
        };
    }

    #endregion

    #region X509 Extensions

    /// <summary>
    /// Filters an <see cref="X509Certificate2Collection"/> using the provided
    /// <paramref name="findType"/> and <paramref name="findValue"/>. If either
    /// parameter is null or empty the original collection is returned.
    /// </summary>
    /// <param name="certificates">Collection to search.</param>
    /// <param name="findType">Optional <see cref="X509FindType"/> as integer.</param>
    /// <param name="findValue">Optional search value (string or OID depending on find type).</param>
    /// <returns>Filtered <see cref="X509Certificate2Collection"/>.</returns>
    public static X509Certificate2Collection FindCertificates(this X509Certificate2Collection certificates, int? findType, string? findValue)
    {
        if (findType.HasValue && !string.IsNullOrWhiteSpace(findValue))
        {
            var x509FindType = (X509FindType)findType;

            switch (x509FindType)
            {
                case X509FindType.FindByThumbprint:
                case X509FindType.FindBySubjectName:
                case X509FindType.FindBySubjectDistinguishedName:
                case X509FindType.FindByIssuerName:
                case X509FindType.FindByIssuerDistinguishedName:
                case X509FindType.FindBySerialNumber:
                    return certificates.Find(x509FindType, findValue, false);
                case X509FindType.FindByTimeValid:
                case X509FindType.FindByTimeNotYetValid:
                case X509FindType.FindByTimeExpired:
                    var timeValue = DateTimeOffset.FromUnixTimeMilliseconds(long.Parse(findValue));
                    return certificates.Find(x509FindType, timeValue.ToLocalTime().DateTime, false);
                case X509FindType.FindByTemplateName:
                    return certificates.Find(x509FindType, findValue, false);
                case X509FindType.FindByApplicationPolicy:
                case X509FindType.FindByCertificatePolicy:
                case X509FindType.FindByExtension:
                    return certificates.Find(x509FindType, new Oid(findValue), false);
                case X509FindType.FindByKeyUsage:
                    var keyUsageValue = (X509KeyUsageFlags)int.Parse(findValue);
                    return certificates.Find(x509FindType, keyUsageValue, false);
                case X509FindType.FindBySubjectKeyIdentifier:
                    //TODO: check findValue is hex string.
                    return certificates.Find(x509FindType, findValue, false);
                default:
                    return certificates;
            }
        }
        else
        {
            return certificates;
        }
    }

    /// <summary>
    /// Normalizes and sorts the Subject DN of a certificate request. The method
    /// updates the request's <see cref="X509.CertificateRequest.SubjectDn"/>
    /// and outputs the common name (CN) if present.
    /// </summary>
    /// <param name="request">Certificate request to modify.</param>
    /// <param name="commonName">Out parameter receiving the CN value if present.</param>
    public static void SortSubjectDn(this X509.CertificateRequest request, out string? commonName)
    {
        var subjectNames = new List<X509.SubjectName>();
        var subjects = request.SubjectDn.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        
        foreach (var subject in subjects)
        {
            var items = subject.Split('=', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            subjectNames.Add(new X509.SubjectName
            {
                Name = items.First(),
                Value = items.Last()
            });
        }

        var sortedSubjects = subjectNames
            .OrderBy(e => e.Order)
            .Select(e => $"{e.Name}={e.Value}");
        request.SubjectDn = string.Join(',', sortedSubjects);

        commonName = subjectNames.SingleOrDefault(e => e.Name.Equals("CN", StringComparison.OrdinalIgnoreCase))?.Value;
    }

    /// <summary>
    /// Converts a <see cref="X509KeyUsageFlags"/> to an actual <see cref="X509KeyUsageExtension"/> instance.
    /// </summary>
    /// <param name="keyUsages">Key usage flags to convert.</param>
    /// <param name="critical">Whether the created extension should be marked critical.</param>
    /// <returns>Constructed <see cref="X509KeyUsageExtension"/>.</returns>
    public static X509KeyUsageExtension ToX509Extension(this X509KeyUsageFlags keyUsages, bool critical = true)
    {
        return new X509KeyUsageExtension(keyUsages, critical);
    }

    /// <summary>
    /// Converts service EKU flags into a .NET <see cref="X509EnhancedKeyUsageExtension"/>
    /// containing the corresponding OIDs for each set flag.
    /// </summary>
    /// <param name="enhancedKeyUsages">EKU flags to convert.</param>
    /// <param name="critical">Whether the created extension should be marked critical.</param>
    /// <returns>Constructed <see cref="X509EnhancedKeyUsageExtension"/>.</returns>
    public static X509EnhancedKeyUsageExtension ToX509Extension(this X509EnhancedKeyUsageFlags enhancedKeyUsages, bool critical = true)
    {
        var enhancedKeyUsageOids = new OidCollection();

        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.AnyExtendedKeyUsage))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeAnyExtendedKeyUsage));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.ClientAuthentication))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeClientAuthentication));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.CodeSigning))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeCodeSigning));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.DocumentSigning))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeDocumentSigning));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.EmailProtection))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeEmailProtection));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.EFS))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeEncryptedFileSystem));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.EFSRecovery))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeEncryptedFileSystemRecovery));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.IntelAMTManagement))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeIntelAMTManagement));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.IPsecIKE))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeIPsecIKE));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.IPsecIKEIntermediate))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeIPsecIKEIntermediate));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.KeyRecovery))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeKeyRecovery));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.MacAddress))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeMacAddress));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.OcspSigning))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeOcspSigning));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.SCVPClient))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeSCVPClient));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.SCVPServer))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeSCVPServer));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.ServerAuthentication))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeServerAuthentication));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.SmartCardLogon))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeSmartCardLogon));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.TimeStamping))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeTimeStamping));
        if (enhancedKeyUsages.HasFlag(X509EnhancedKeyUsageFlags.TSLSigning))
            enhancedKeyUsageOids.Add(new Oid(Oids.KeyPurposeTSLSigning));

        return new X509EnhancedKeyUsageExtension(enhancedKeyUsageOids, critical);
    }

    /// <summary>
    /// Converts a .NET <see cref="X509ExtensionCollection"/> into a BouncyCastle
    /// <see cref="BcX509.X509Extensions"/> instance preserving OIDs and raw extension values.
    /// </summary>
    /// <param name="extensions">Collection of X509 extensions to convert.</param>
    /// <returns>BouncyCastle representation of the extensions.</returns>
    public static BcX509.X509Extensions ToX509Extensions(this X509ExtensionCollection extensions)
    {
        var extensionList = extensions.Select(e => new { e.Oid, e.RawData }).ToList();
        var oidList = extensions.Select(e => new DerObjectIdentifier(e.Oid!.Value)).ToList();
        var valueList = extensions.Select(e =>
            new BcX509.X509Extension(e.Critical, Asn1OctetString.GetInstance(new DerOctetString(e.RawData)))
        ).ToList();
        return new BcX509.X509Extensions(oidList, valueList);
    }

    #endregion

    #region Exception Extensions

    /// <summary>
    /// Creates friendly error messages for known PKCS#11 exceptions, enhancing
    /// operator understanding of issues. Extracts numeric error codes when possible
    /// and translates them into human-readable messages.
    /// </summary>
    /// <param name="ex">The exception to analyze.</param>
    /// <returns>A user-friendly error message.</returns>
    public static string GetFriendlyMessage(this Exception ex)
    {
        if (ex is Pkcs11Exception pkex)
            return pkex.Translate();
        if (ex.InnerException is Pkcs11Exception pkInner)
            return pkInner.Translate();

        return ex.ToFullMessage();
    }

    /// <summary>
    /// Maps known PKCS#11 exception text or properties to a numeric error code
    /// defined by <c>Pkcs11ErrorCodes</c> used by the service.
    /// </summary>
    /// <param name="ex">Exception to inspect.</param>
    /// <returns>Integer error code representing the PKCS#11 condition.</returns>
    public static int GetPkcs11ErrorCode(this Exception ex)
    {
        if (ex == null) return Pkcs11ErrorCodes.Unknown;

        Pkcs11Exception? pkex = ex as Pkcs11Exception ?? ex.InnerException as Pkcs11Exception;
        string message = pkex?.Message ?? ex.Message ?? string.Empty;
        var text = message.ToUpperInvariant();

        if (text.Contains("USER_TYPE_INVALID") || text.Contains("CKR_USER_TYPE_INVALID"))
            return Pkcs11ErrorCodes.UserTypeInvalid;
        if (text.Contains("PIN_INCORRECT") || text.Contains("CKR_PIN_INCORRECT"))
            return Pkcs11ErrorCodes.PinIncorrect;
        if (text.Contains("PIN_LOCKED") || text.Contains("CKR_PIN_LOCKED") || text.Contains("USER_PIN_LOCKED"))
            return Pkcs11ErrorCodes.PinLocked;
        if (text.Contains("USER_ALREADY_LOGGED_IN") || text.Contains("CKR_USER_ALREADY_LOGGED_IN"))
            return Pkcs11ErrorCodes.UserAlreadyLoggedIn;
        if (text.Contains("USER_NOT_LOGGED_IN") || text.Contains("CKR_USER_NOT_LOGGED_IN"))
            return Pkcs11ErrorCodes.UserNotLoggedIn;
        if (text.Contains("USER_PIN_NOT_INITIALIZED") || text.Contains("CKR_USER_PIN_NOT_INITIALIZED"))
            return Pkcs11ErrorCodes.UserPinNotInitialized;
        if (text.Contains("DEVICE_ERROR") || text.Contains("CKR_DEVICE_ERROR"))
            return Pkcs11ErrorCodes.DeviceError;

        return Pkcs11ErrorCodes.Unknown;
    }

    /// <summary>
    /// Builds a full message chain from an exception and its inner exceptions
    /// by concatenating all contained messages.
    /// </summary>
    /// <param name="ex">Exception to inspect.</param>
    /// <returns>Concatenated messages from the exception chain.</returns>
    public static string ToFullMessage(this Exception ex)
    {
        var messages = new StringBuilder();
        var currentEx = ex;
        while (currentEx != null)
        {
            messages.AppendLine(currentEx.Message);
            currentEx = currentEx.InnerException;
        }
        return messages.ToString();
    }

    /// <summary>
    /// Translate well-known PKCS#11 error conditions to actionable messages for
    /// operators or clients. Attempts to read numeric return codes via reflection
    /// and falls back to message inspection when needed.
    /// </summary>
    /// <param name="ex">The PKCS#11 exception to translate.</param>
    /// <returns>User-friendly explanation of the PKCS#11 failure.</returns>
    public static string Translate(this Pkcs11Exception ex)
    {
        try
        {
            // Try common property names to get a numeric/enum return value
            var type = ex.GetType();
            var prop = type.GetProperty("RV") ?? type.GetProperty("ReturnValue") ?? type.GetProperty("ErrorCode") ?? type.GetProperty("CKR");
            string? codeText = null;
            if (prop != null)
            {
                var val = prop.GetValue(ex);
                codeText = val?.ToString();
            }

            // Fall back to message text if no structured code found
            var message = codeText ?? ex.Message ?? string.Empty;
            message = message.ToUpperInvariant();

            if (message.Contains("USER_TYPE_INVALID") || message.Contains("CKR_USER_TYPE_INVALID"))
                return "Invalid user type for login. Ensure you are using the correct login type (user vs SO) and device supports it.";
            if (message.Contains("PIN_INCORRECT") || message.Contains("CKR_PIN_INCORRECT"))
                return "The provided PIN is incorrect. Retry or cancel. If you repeatedly enter an incorrect PIN the token may lock.";
            if (message.Contains("PIN_LOCKED") || message.Contains("CKR_PIN_LOCKED") || message.Contains("USER_PIN_LOCKED"))
                return "The PIN is locked. Unlock or reset the PIN using SO (Security Officer) commands or vendor tools.";
            if (message.Contains("USER_ALREADY_LOGGED_IN") || message.Contains("CKR_USER_ALREADY_LOGGED_IN"))
                return "User is already logged in. Possibly another session has authenticated. Try logging out other sessions or reusing the existing session.";
            if (message.Contains("USER_NOT_LOGGED_IN") || message.Contains("CKR_USER_NOT_LOGGED_IN"))
                return "User is not logged in. A login is required before performing this operation.";
            if (message.Contains("USER_PIN_NOT_INITIALIZED") || message.Contains("CKR_USER_PIN_NOT_INITIALIZED"))
                return "User PIN is not initialized. Initialize the PIN (often via SO) before attempting to login.";
            if (message.Contains("DEVICE_ERROR") || message.Contains("CKR_DEVICE_ERROR"))
                return "Device reported an error. Check the hardware, drivers and vendor logs.";

            // Default: return original exception message for debugging
            return ex.Message ?? "PKCS#11 operation failed.";
        }
        catch
        {
            return ex.Message ?? "PKCS#11 operation failed.";
        }
    }

    #endregion
}
