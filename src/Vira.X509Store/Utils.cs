using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace Vira.X509Store;

/// <summary>
/// Helper utilities used across the X509 store service.
/// </summary>
/// <remarks>
/// This internal static class contains pure helper/utility methods for:
/// - filename normalization,
/// - parsing X.509 names,
/// - ASN.1 signature encoding/decoding,
/// - PKCS#11 mechanism/parameter helpers,
/// - mapping between PKCS#11 CKM and digest/signature constructs,
/// - conversions for EC/RSA public key parameters and other small helpers.
///
/// Methods are implemented as extensions or plain static helpers and intentionally
/// do not change application state. They throw well-known exceptions for invalid input
/// or unsupported algorithms/mechanisms.
/// </remarks>
internal static class Utils
{
    // Message used when an unsupported hash algorithm is encountered.
    private static readonly string NotSupportedHashAlgorithm = "Hash algorithm is not supported.";

    // Message used when an unsupported signature mechanism is encountered.
    private static readonly string NotSupportedSignatureMechanism = "Signature mechanism is not supported.";

    /// <summary>
    /// Normalize an arbitrary filename by replacing invalid file name characters with underscores.
    /// </summary>
    /// <param name="fileName">Input file name to normalize. Cannot be null or empty.</param>
    /// <returns>A file-system safe file name where invalid characters are replaced by underscores.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="fileName"/> is null or empty.</exception>
    public static string NormalizeFileName(string fileName)
    {
        if (string.IsNullOrEmpty(fileName))
            throw new ArgumentNullException(nameof(fileName));

        return string.Join("_", fileName.Split(Path.GetInvalidFileNameChars()));
    }

    /// <summary>
    /// Parse a BouncyCastle <see cref="X509Name"/> into a dictionary keyed by OID string.
    /// </summary>
    /// <param name="x509Name">The X509Name instance to parse (must not be null).</param>
    /// <returns>
    /// Dictionary where the key is the OID string (e.g. "2.5.4.3") and the value is a list of
    /// attribute string values found for that OID in the RDN sequence.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="x509Name"/> is null.</exception>
    public static Dictionary<string, List<string>> ParseX509Name(X509Name x509Name)
    {
        ArgumentNullException.ThrowIfNull(x509Name, nameof(x509Name));

        var parts = new Dictionary<string, List<string>>();

        var oidList = x509Name.GetOidList();
        var valueList = x509Name.GetValueList();

        for (int i = 0; i < oidList.Count; i++)
        {
            var oid = oidList[i];
            var item = valueList[i];

            if (!parts.TryGetValue(oid.Id, out List<string>? value))
                parts.Add(oid.Id, [item]);
            else
                value.Add(item);
        }

        return parts;
    }

    /// <summary>
    /// Create an ASN.1 DigestInfo (DER encoded) for a given raw hash and its hash OID.
    /// </summary>
    /// <param name="hash">Raw hash bytes (e.g. SHA-256 digest).</param>
    /// <param name="hashOid">OID string of the hash algorithm (e.g. Oids.Sha256).</param>
    /// <returns>DER encoded DigestInfo structure.</returns>
    public static byte[] CreateDigestInfo(byte[] hash, string hashOid)
    {
        var derObjectIdentifier = new DerObjectIdentifier(hashOid);
        var algorithmIdentifier = new AlgorithmIdentifier(derObjectIdentifier, DerNull.Instance);
        var digestInfo = new DigestInfo(algorithmIdentifier, hash);
        return digestInfo.GetDerEncoded();
    }

    /// <summary>
    /// Decode a DER-encoded ECDSA signature (ASN.1 SEQUENCE of two INTEGERs) into a
    /// fixed-length raw concatenated (r || s) signature expected by some PKCS#11 tokens.
    /// </summary>
    /// <param name="derSignature">DER encoded signature bytes.</param>
    /// <returns>
    /// A 64-byte array (32 bytes r + 32 bytes s) for P-256 style signatures or null if decoding fails.
    /// </returns>
    /// <exception cref="Exception">Throws a generic exception when DER decoding fails due to IO error.</exception>
    public static byte[]? DecodeFromAsn1DerSignature(byte[] derSignature)
    {
        try
        {
            DerInteger r, s;
            using var decoder = new Asn1InputStream(derSignature);
            var seq = (Asn1Sequence)decoder.ReadObject();

            try
            {
                r = (DerInteger)seq[0];
                s = (DerInteger)seq[1];
            }
            catch (InvalidCastException)
            {
                return null;
            }

            var ecSignature = new byte[64];
            Array.Copy(r.PositiveValue.ToByteArray(), 0, ecSignature, 0, 32);
            Array.Copy(s.PositiveValue.ToByteArray(), 0, ecSignature, 32, 32);

            return ecSignature;
        }
        catch (IOException e)
        {
            throw new Exception("Decoding form DER failed", e);
        }
    }

    /// <summary>
    /// Encode a raw concatenated ECDSA signature (r || s) into ASN.1 DER format (SEQUENCE of INTEGERs).
    /// </summary>
    /// <param name="pkcs11Signature">Raw signature bytes expected to contain r and s concatenated.</param>
    /// <returns>DER encoded signature bytes.</returns>
    public static byte[] EncodeToAsn1DerSignature(byte[] pkcs11Signature)
    {
        var len = pkcs11Signature.Length / 2;
        // first 32 bytes is "r" number
        var r = new DerInteger(new BigInteger(1, [.. pkcs11Signature.Take(len)]));
        // last 32 bytes is "s" number
        var s = new DerInteger(new BigInteger(1, [.. pkcs11Signature.Skip(len)]));
        var derSignature = new DerSequence(r, s);

        return derSignature.GetDerEncoded();
    }

    /// <summary>
    /// Creates CKR_RSA_PKCS_PSS mechanism parameters for the provided hash algorithm.
    /// </summary>
    /// <param name="session">PKCS#11 session used to create mechanism parameters.</param>
    /// <param name="hashAlgorithm">Hash mechanism (CKM) to use for PSS.</param>
    /// <returns>Mechanism parameters object suitable for CKM_RSA_PKCS_PSS operations.</returns>
    /// <exception cref="CryptographicException">Thrown when the specified hash algorithm is not supported.</exception>
    public static ICkRsaPkcsPssParams CreateCkRsaPkcsPssParams(ISession session, CKM hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            CKM.CKM_SHA_1 => session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                                hashAlg: (ulong)CKM.CKM_SHA_1,
                                mgf: (ulong)CKG.CKG_MGF1_SHA1,
                                len: (ulong)GetHashGenerator(hashAlgorithm).GetDigestSize()
                            ),
            CKM.CKM_SHA256 => session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                                hashAlg: (ulong)CKM.CKM_SHA256,
                                mgf: (ulong)CKG.CKG_MGF1_SHA256,
                                len: (ulong)GetHashGenerator(hashAlgorithm).GetDigestSize()
                            ),
            CKM.CKM_SHA384 => session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                                hashAlg: (ulong)CKM.CKM_SHA384,
                                mgf: (ulong)CKG.CKG_MGF1_SHA384,
                                len: (ulong)GetHashGenerator(hashAlgorithm).GetDigestSize()
                            ),
            CKM.CKM_SHA512 => session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                                hashAlg: (ulong)CKM.CKM_SHA512,
                                mgf: (ulong)CKG.CKG_MGF1_SHA512,
                                len: (ulong)GetHashGenerator(hashAlgorithm).GetDigestSize()
                            ),
            _ => throw new CryptographicException(NotSupportedHashAlgorithm),
        };
    }

    /// <summary>
    /// Return a BouncyCastle digest implementation for the requested CKM hash mechanism.
    /// </summary>
    /// <param name="hashAlgorithm">CKM hash mechanism identifier.</param>
    /// <returns>Implementation of <see cref="IDigest"/> for the algorithm.</returns>
    /// <exception cref="CryptographicException">Thrown when the algorithm is not supported.</exception>
    public static IDigest GetHashGenerator(CKM hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            CKM.CKM_SHA_1 => new Sha1Digest(),
            CKM.CKM_SHA256 => new Sha256Digest(),
            CKM.CKM_SHA384 => new Sha384Digest(),
            CKM.CKM_SHA512 => new Sha512Digest(),
            _ => throw new CryptographicException(NotSupportedHashAlgorithm),
        };
    }

    /// <summary>
    /// Extracts digest/signature mapping and OID information from a PKCS#11 mechanism.
    /// </summary>
    /// <param name="mechanismType">PKCS#11 CKM mechanism to analyze.</param>
    /// <param name="hashMechanismType">Output CKM hash mechanism corresponding to <paramref name="mechanismType"/>.</param>
    /// <param name="signMechanismType">Output CKM signing mechanism (RSA/ECDSA/PSS) for the mechanism.</param>
    /// <param name="hashAlgorithmOid">Output OID string for the digest algorithm (e.g. Oids.Sha256).</param>
    /// <exception cref="CryptographicException">Thrown when the mechanism is not supported.</exception>
    public static void ExtractMechanismType(CKM mechanismType, out CKM hashMechanismType, out CKM signMechanismType, out string hashAlgorithmOid)
    {
        switch (mechanismType)
        {
            case CKM.CKM_SHA1_RSA_PKCS:
                hashAlgorithmOid = Oids.Sha1;
                hashMechanismType = CKM.CKM_SHA_1;
                signMechanismType = CKM.CKM_RSA_PKCS;
                break;
            case CKM.CKM_SHA224_RSA_PKCS:
                hashAlgorithmOid = Oids.Sha224;
                hashMechanismType = CKM.CKM_SHA224;
                signMechanismType = CKM.CKM_RSA_PKCS;
                break;
            case CKM.CKM_SHA256_RSA_PKCS:
                hashAlgorithmOid = Oids.Sha256;
                hashMechanismType = CKM.CKM_SHA256;
                signMechanismType = CKM.CKM_RSA_PKCS;
                break;
            case CKM.CKM_SHA384_RSA_PKCS:
                hashAlgorithmOid = Oids.Sha384;
                hashMechanismType = CKM.CKM_SHA384;
                signMechanismType = CKM.CKM_RSA_PKCS;
                break;
            case CKM.CKM_SHA512_RSA_PKCS:
                hashAlgorithmOid = Oids.Sha512;
                hashMechanismType = CKM.CKM_SHA512;
                signMechanismType = CKM.CKM_RSA_PKCS;
                break;
            case CKM.CKM_SHA1_RSA_PKCS_PSS:
                hashAlgorithmOid = Oids.Sha1;
                hashMechanismType = CKM.CKM_SHA_1;
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                break;
            case CKM.CKM_SHA224_RSA_PKCS_PSS:
                hashAlgorithmOid = Oids.Sha224;
                hashMechanismType = CKM.CKM_SHA224;
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                break;
            case CKM.CKM_SHA256_RSA_PKCS_PSS:
                hashAlgorithmOid = Oids.Sha256;
                hashMechanismType = CKM.CKM_SHA256;
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                break;
            case CKM.CKM_SHA384_RSA_PKCS_PSS:
                hashAlgorithmOid = Oids.Sha384;
                hashMechanismType = CKM.CKM_SHA384;
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                break;
            case CKM.CKM_SHA512_RSA_PKCS_PSS:
                hashAlgorithmOid = Oids.Sha512;
                hashMechanismType = CKM.CKM_SHA512;
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                break;
            case CKM.CKM_ECDSA_SHA1:
                hashAlgorithmOid = Oids.Sha1;
                hashMechanismType = CKM.CKM_SHA_1;
                signMechanismType = CKM.CKM_ECDSA;
                break;
            case CKM.CKM_ECDSA_SHA224:
                hashAlgorithmOid = Oids.Sha224;
                hashMechanismType = CKM.CKM_SHA224;
                signMechanismType = CKM.CKM_ECDSA;
                break;
            case CKM.CKM_ECDSA_SHA256:
                hashAlgorithmOid = Oids.Sha256;
                hashMechanismType = CKM.CKM_SHA256;
                signMechanismType = CKM.CKM_ECDSA;
                break;
            case CKM.CKM_ECDSA_SHA384:
                hashAlgorithmOid = Oids.Sha384;
                hashMechanismType = CKM.CKM_SHA384;
                signMechanismType = CKM.CKM_ECDSA;
                break;
            case CKM.CKM_ECDSA_SHA512:
                hashAlgorithmOid = Oids.Sha512;
                hashMechanismType = CKM.CKM_SHA512;
                signMechanismType = CKM.CKM_ECDSA;
                break;
            default:
                throw new CryptographicException(NotSupportedHashAlgorithm);
        }
    }

    /// <summary>
    /// Returns the fixed digest size in bytes for supported CKM hash algorithms.
    /// </summary>
    /// <param name="hashAlgorithm">CKM hash algorithm identifier.</param>
    /// <returns>Digest size in bytes.</returns>
    /// <exception cref="CryptoException">Thrown when the algorithm is not supported.</exception>
    public static int GetDigestSize(CKM hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            CKM.CKM_SHA_1 => 20,
            CKM.CKM_SHA224 => 28,
            CKM.CKM_SHA256 => 32,
            CKM.CKM_SHA384 => 48,
            CKM.CKM_SHA512 => 64,
            _ => throw new CryptoException(NotSupportedHashAlgorithm),
        };
    }

    /// <summary>
    /// Retuens the object size of an object handle from the token, returning null on failure.
    /// </summary>
    /// <param name="session">PKCS#11 session.</param>
    /// <param name="objectHandle">Object handle to query.</param>
    /// <returns>Object size in bytes or null if the size cannot be read.</returns>
    public static ulong? GetObjectSize(ISession session, IObjectHandle objectHandle)
    {
        ulong? size = null;

        try
        {
            size = session.GetObjectSize(objectHandle);
        }
        catch
        {
        }

        return size;
    }

    /// <summary>
    /// Read EC public key parameters from a PKCS#11 public key object.
    /// </summary>
    /// <param name="session">PKCS#11 session to use for attribute retrieval.</param>
    /// <param name="keyHandle">Handle to the public key object.</param>
    /// <param name="label">Out parameter that receives the key label from the token.</param>
    /// <returns>BouncyCastle <see cref="ECPublicKeyParameters"/> representing the public key.</returns>
    public static ECPublicKeyParameters GetEcPublicKeyParams(ISession session, IObjectHandle keyHandle, out string label)
    {
        var publicKeyAttributes = session.GetAttributeValue(keyHandle, [CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT, CKA.CKA_LABEL]);
        var ecParams = publicKeyAttributes[0].GetValueAsByteArray();
        var ecPoint = publicKeyAttributes[1].GetValueAsByteArray();
        label = publicKeyAttributes[2].GetValueAsString();

        var curveParams = X9ECParameters.GetInstance(Asn1Sequence.GetInstance(ecParams));
        var curve = curveParams.Curve;
        var octetString = Asn1OctetString.GetInstance(Asn1Object.FromByteArray(ecPoint));
        var x9EcPoint = new X9ECPoint(curve, octetString);
        var domainParams = new ECDomainParameters(curve, curveParams.G, curveParams.N, curveParams.H);

        return new ECPublicKeyParameters(x9EcPoint.Point, domainParams);
    }

    /// <summary>
    /// Read RSA public key parameters from a PKCS#11 public key object.
    /// </summary>
    /// <param name="session">PKCS#11 session to use for attribute retrieval.</param>
    /// <param name="keyHandle">Handle to the public key object.</param>
    /// <param name="label">Out parameter that receives the key label from the token.</param>
    /// <returns>BouncyCastle <see cref="RsaKeyParameters"/> representing the public key.</returns>
    public static RsaKeyParameters GetRsaPublicKeyParams(ISession session, IObjectHandle keyHandle, out string label)
    {
        var publicKeyAttributes = session.GetAttributeValue(keyHandle, [CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT, CKA.CKA_LABEL]);
        var modulus = new BigInteger(1, publicKeyAttributes[0].GetValueAsByteArray());
        var publicExponent = new BigInteger(1, publicKeyAttributes[1].GetValueAsByteArray());
        label = publicKeyAttributes[2].GetValueAsString();

        return new RsaKeyParameters(false, modulus, publicExponent);
    }

    /// <summary>
    /// Return the signature algorithm OID for a PKCS#11 mechanism type.
    /// </summary>
    /// <param name="mechanismType">CKM mechanism identifier (e.g. CKM_SHA256_RSA_PKCS).</param>
    /// <returns>Corresponding signature algorithm OID string.</returns>
    /// <exception cref="CryptographicException">Thrown when the mechanism is not supported.</exception>
    public static string GetSignatureAlgorithmOid(CKM mechanismType)
    {
        return mechanismType switch
        {
            CKM.CKM_SHA1_RSA_PKCS or CKM.CKM_SHA1_RSA_PKCS_PSS => Oids.RsaPkcs1Sha1,
            CKM.CKM_SHA224_RSA_PKCS or CKM.CKM_SHA224_RSA_PKCS_PSS => Oids.RsaPkcs1Sha224,
            CKM.CKM_SHA256_RSA_PKCS or CKM.CKM_SHA256_RSA_PKCS_PSS => Oids.RsaPkcs1Sha256,
            CKM.CKM_SHA384_RSA_PKCS or CKM.CKM_SHA384_RSA_PKCS_PSS => Oids.RsaPkcs1Sha384,
            CKM.CKM_SHA512_RSA_PKCS or CKM.CKM_SHA512_RSA_PKCS_PSS => Oids.RsaPkcs1Sha512,
            CKM.CKM_ECDSA_SHA1 => Oids.ECDsaWithSha1,
            CKM.CKM_ECDSA_SHA224 => Oids.ECDsaWithSha224,
            CKM.CKM_ECDSA_SHA256 => Oids.ECDsaWithSha256,
            CKM.CKM_ECDSA_SHA384 => Oids.ECDsaWithSha384,
            CKM.CKM_ECDSA_SHA512 => Oids.ECDsaWithSha512,
            _ => throw new CryptographicException(NotSupportedSignatureMechanism),
        };
    }

    /// <summary>
    /// Create a BouncyCastle signer instance for the provided PKCS#11 mechanism and
    /// return the underlying sign mechanism type used with the token.
    /// </summary>
    /// <param name="mechanismType">CKM mechanism identifier.</param>
    /// <param name="signMechanismType">Out parameter receiving the sign mechanism to use on the token.</param>
    /// <returns>Configured <see cref="ISigner"/> instance ready to sign or verify data.</returns>
    /// <exception cref="CryptographicException">Thrown when mechanism is not supported.</exception>
    public static ISigner GetSigner(CKM mechanismType, out CKM signMechanismType)
    {
        switch (mechanismType)
        {
            case CKM.CKM_SHA1_RSA_PKCS:
                signMechanismType = CKM.CKM_RSA_PKCS;
                return SignerUtilities.GetSigner("SHA-1withRSA");
            case CKM.CKM_SHA224_RSA_PKCS:
                signMechanismType = CKM.CKM_RSA_PKCS;
                return SignerUtilities.GetSigner("SHA-224withRSA");
            case CKM.CKM_SHA256_RSA_PKCS:
                signMechanismType = CKM.CKM_RSA_PKCS;
                return SignerUtilities.GetSigner("SHA-256withRSA");
            case CKM.CKM_SHA384_RSA_PKCS:
                signMechanismType = CKM.CKM_RSA_PKCS;
                return SignerUtilities.GetSigner("SHA-384withRSA");
            case CKM.CKM_SHA512_RSA_PKCS:
                signMechanismType = CKM.CKM_RSA_PKCS;
                return SignerUtilities.GetSigner("SHA-512withRSA");
            case CKM.CKM_SHA1_RSA_PKCS_PSS:
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                return new PssSigner(new RsaBlindedEngine(), new Sha1Digest());
            case CKM.CKM_SHA224_RSA_PKCS_PSS:
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                return new PssSigner(new RsaBlindedEngine(), new Sha224Digest());
            case CKM.CKM_SHA256_RSA_PKCS_PSS:
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                return new PssSigner(new RsaBlindedEngine(), new Sha256Digest());
            case CKM.CKM_SHA384_RSA_PKCS_PSS:
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                return new PssSigner(new RsaBlindedEngine(), new Sha384Digest());
            case CKM.CKM_SHA512_RSA_PKCS_PSS:
                signMechanismType = CKM.CKM_RSA_PKCS_PSS;
                return new PssSigner(new RsaBlindedEngine(), new Sha512Digest());
            case CKM.CKM_ECDSA_SHA1:
                signMechanismType = CKM.CKM_ECDSA;
                return SignerUtilities.GetSigner("SHA-1withECDSA");
            case CKM.CKM_ECDSA_SHA224:
                signMechanismType = CKM.CKM_ECDSA;
                return SignerUtilities.GetSigner("SHA-224withECDSA");
            case CKM.CKM_ECDSA_SHA256:
                signMechanismType = CKM.CKM_ECDSA;
                return SignerUtilities.GetSigner("SHA-256withECDSA");
            case CKM.CKM_ECDSA_SHA384:
                signMechanismType = CKM.CKM_ECDSA;
                return SignerUtilities.GetSigner("SHA-384withECDSA");
            case CKM.CKM_ECDSA_SHA512:
                signMechanismType = CKM.CKM_ECDSA;
                return SignerUtilities.GetSigner("SHA-512withECDSA");
            default:
                throw new CryptographicException(NotSupportedSignatureMechanism);
        }
    }

    /// <summary>
    /// Return X9.62 parameters for the specified elliptic curve enum value.
    /// </summary>
    /// <param name="ellipticCurve">Curve identifier enum.</param>
    /// <returns><see cref="X962Parameters"/> instance for the requested curve.</returns>
    public static X962Parameters GetX962Parameters(EllipticCurveFlags ellipticCurve)
    {
        return ellipticCurve switch
        {
            EllipticCurveFlags.brainpoolP160r1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP160r1")),
            EllipticCurveFlags.brainpoolP160t1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP160t1")),
            EllipticCurveFlags.brainpoolP192r1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP192r1")),
            EllipticCurveFlags.brainpoolP192t1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP192t1")),
            EllipticCurveFlags.brainpoolP224r1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP224r1")),
            EllipticCurveFlags.brainpoolP224t1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP224t1")),
            EllipticCurveFlags.brainpoolP256r1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP256r1")),
            EllipticCurveFlags.brainpoolP256t1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP256t1")),
            EllipticCurveFlags.brainpoolP320r1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP320r1")),
            EllipticCurveFlags.brainpoolP320t1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP320t1")),
            EllipticCurveFlags.brainpoolP384r1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP384r1")),
            EllipticCurveFlags.brainpoolP384t1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP384t1")),
            EllipticCurveFlags.brainpoolP512r1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP512r1")),
            EllipticCurveFlags.brainpoolP512t1 => new X962Parameters(TeleTrusTNamedCurves.GetByName("brainpoolP512t1")),
            EllipticCurveFlags.nistP256 => new X962Parameters(NistNamedCurves.GetByName("P-256")),
            EllipticCurveFlags.nistP384 => new X962Parameters(NistNamedCurves.GetByName("P-384")),
            EllipticCurveFlags.nistP521 => new X962Parameters(NistNamedCurves.GetByName("P-521")),
            _ => new X962Parameters(NistNamedCurves.GetByName("P-256")),
        };
    }
}
