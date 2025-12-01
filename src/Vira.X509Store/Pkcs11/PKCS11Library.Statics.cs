using Microsoft.Extensions.Logging;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Vira.X509Store.Pkcs11;
using AlgorithmIdentifier = Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using IssuerAndSerialNumber = Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;
using SignerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo;
using Time = Org.BouncyCastle.Asn1.Cms.Time;

namespace Vira.X509Store.Service;

public partial class PKCS11Library
{
    private static readonly string NotSupportedKeyAlgorithm = "Key algorithm is not supported.";
    private static readonly string NotSupportedKeyType = "Key type is not supported.";
    private static readonly string NotSupportedEcKeyType = "ECDsa key type is not supported.";
    private static readonly string NotSupportedRsaKeyType = "RSA key type is not supported.";

    public static void DigestEncrypt(ISession session,
                                     KeyInfo pubKeyInfo,
                                     CKM digestMechanismType,
                                     CKM encryptionMechanismType,
                                     byte[] data,
                                     out byte[] digest,
                                     out byte[] encryptedData)
    {
        using var digestMechanism = session.Factories.MechanismFactory.Create(digestMechanismType);
        using var encryptionMechanism = session.Factories.MechanismFactory.Create(encryptionMechanismType);
        session.DigestEncrypt(digestMechanism, encryptionMechanism, pubKeyInfo.ObjectHandle, data, out digest, out encryptedData);
    }

    public static void DecryptDigest(ISession session,
                                     KeyInfo privKeyInfo,
                                     CKM digestMechanismType,
                                     CKM encryptionMechanismType,
                                     byte[] encryptedData,
                                     out byte[] digest,
                                     out byte[] decryptedData)
    {
        using var digestMechanism = session.Factories.MechanismFactory.Create(digestMechanismType);
        using var encryptionMechanism = session.Factories.MechanismFactory.Create(encryptionMechanismType);
        session.DecryptDigest(digestMechanism, encryptionMechanism, privKeyInfo.ObjectHandle, encryptedData, out digest, out decryptedData);
    }

    public static void Encrypt(ISession session,
                               KeyInfo pubKeyInfo,
                               CKM mechanismType,
                               byte[] data,
                               out byte[] encryptedData)
    {
        using var mechanism = session.Factories.MechanismFactory.Create(mechanismType);
        encryptedData = session.Encrypt(mechanism, pubKeyInfo.ObjectHandle, data);
    }

    public static void Decrypt(ISession session,
                               KeyInfo privKeyInfo,
                               CKM mechanismType,
                               byte[] encryptedData,
                               out byte[] decryptedData)
    {
        using var mechanism = session.Factories.MechanismFactory.Create(mechanismType);
        decryptedData = session.Decrypt(mechanism, privKeyInfo.ObjectHandle, encryptedData);
    }

    public static void GenerateCsrPEM(ISession session,
                                      CKK keyType,
                                      IObjectHandle publicKeyHandle,
                                      IObjectHandle privateKeyHandle,
                                      X500DistinguishedName subjectDn,
                                      CKM mechanismType,
                                      X509Extensions extensions,
                                      out string pkcs10CSR)
    {
        AsymmetricKeyParameter publicKeyParameters;
        var x509Name = X509Name.GetInstance(subjectDn.RawData);

        if (keyType == CKK.CKK_RSA)
        {
            publicKeyParameters = Utils.GetRsaPublicKeyParams(session, publicKeyHandle, out _);
        }
        else if (keyType == CKK.CKK_EC || keyType == CKK.CKK_ECDSA)
        {
            publicKeyParameters = Utils.GetEcPublicKeyParams(session, publicKeyHandle, out _);
        }
        else
        {
            throw new CryptographicException(NotSupportedKeyType);
        }

        var signatureAlgorithmOid = Utils.GetSignatureAlgorithmOid(mechanismType);
        var pkcsAttribute = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));
        var attributes = new DerSet(pkcsAttribute);
        var pkcs10 = new Pkcs10CertificationRequestDelaySigned(signatureAlgorithmOid, x509Name, publicKeyParameters, attributes);

        Sign(session, privateKeyHandle, mechanismType, pkcs10.GetDataToSign(), out byte[] csrSignature);
        pkcs10.SignRequest(csrSignature);
        var csr = Convert.ToBase64String(pkcs10.GetDerEncoded(), Base64FormattingOptions.InsertLineBreaks);
        pkcs10CSR = $"-----BEGIN CERTIFICATE REQUEST-----\n{csr}\n-----END CERTIFICATE REQUEST-----";
    }

    public static void GenerateCsrDER(ISession session,
                                      KeyInfo privKeyInfo,
                                      KeyInfo pubKeyInfo,
                                      X500DistinguishedName subjectDn,
                                      CKM mechanismType,
                                      X509Extensions extensions,
                                      out byte[] pkcs10CSR)
    {
        AsymmetricKeyParameter publicKeyParameters;
        var keyType = (CKK)privKeyInfo.CkaKeyType;
        var signatureAlgorithmOid = Utils.GetSignatureAlgorithmOid(mechanismType);
        var x509Name = X509Name.GetInstance(subjectDn.RawData);

        if (keyType == CKK.CKK_RSA)
        {
            publicKeyParameters = Utils.GetRsaPublicKeyParams(session, pubKeyInfo.ObjectHandle, out _);
        }
        else if (keyType == CKK.CKK_EC || keyType == CKK.CKK_ECDSA)
        {
            publicKeyParameters = Utils.GetEcPublicKeyParams(session, pubKeyInfo.ObjectHandle, out _);
        }
        else
        {
            throw new CryptographicException(NotSupportedKeyType);
        }

        var pkcsAttribute = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));
        var attributes = new DerSet(pkcsAttribute);
        var pkcs10 = new Pkcs10CertificationRequestDelaySigned(signatureAlgorithmOid, x509Name, publicKeyParameters, attributes);

        Sign(session, privKeyInfo.ObjectHandle, mechanismType, pkcs10.GetDataToSign(), out byte[] signature);
        pkcs10.SignRequest(new DerBitString(signature));

        pkcs10CSR = pkcs10.GetDerEncoded();
    }

    public static IObjectHandle ImportCertificate(ISession session,
                                                  X509Certificate2 certificate,
                                                  byte[] keyId,
                                                  string label)
    {
        var certificateAttributes = new List<IObjectAttribute>
        {
            // Common Storage Object Attributes
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            // Common Certificate Object Attributes
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            // Advanced Certificate Object Attributes
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, certificate.SubjectName.RawData),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, certificate.IssuerName.RawData),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, certificate.SerialNumber),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, certificate.RawData),

            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TRUSTED, false),
        };

        return session.CreateObject(certificateAttributes);
    }

    public static IObjectHandle ImportCertificate(ISession session,
                                                  byte[] rawData,
                                                  byte[] keyId,
                                                  string label)
    {
        var x509CertificateParser = new X509CertificateParser();
        var x509Certificate = x509CertificateParser.ReadCertificate(rawData);

        var skidOid = new DerObjectIdentifier(Oids.SubjectKeyIdentifier);
        var skidExtension = x509Certificate.CertificateStructure.TbsCertificate.Extensions.GetExtension(skidOid);
        var subjectKeyIdentifier = SubjectKeyIdentifier.GetInstance(skidExtension).GetKeyIdentifier();

        var akidOid = new DerObjectIdentifier(Oids.AuthorityKeyIdentifier);
        var akidExtension = x509Certificate.CertificateStructure.TbsCertificate.Extensions.GetExtension(akidOid);
        var authorityKeyIdentifier = akidExtension != null
            ? AuthorityKeyIdentifier.GetInstance(akidExtension).GetKeyIdentifier()
            : subjectKeyIdentifier;

        // set up CK object with certificate attributes
        var certificateAttributes = new List<IObjectAttribute>
        {
            // Common Storage Object Attributes
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            // Common Certificate Object Attributes
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_START_DATE, x509Certificate.NotBefore),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_END_DATE, x509Certificate.NotAfter),
            // Advanced Certificate Object Attributes
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()),
            //session.Factories.ObjectAttributeFactory.Create(CKA.CKA_OWNER, x509Certificate.SubjectUniqueID.GetDerEncoded()),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_HASH_OF_SUBJECT_PUBLIC_KEY, subjectKeyIdentifier),
            //session.Factories.ObjectAttributeFactory.Create(CKA.CKA_AC_ISSUER, x509Certificate.IssuerUniqueID.GetDerEncoded()),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_HASH_OF_ISSUER_PUBLIC_KEY, authorityKeyIdentifier),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, new DerInteger(x509Certificate.SerialNumber).GetDerEncoded()),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, x509Certificate.GetEncoded()),
        };

        return session.CreateObject(certificateAttributes);
    }

    public static void Sign(ISession session,
                            IObjectHandle privKeyHandle,
                            CKM mechanismType,
                            byte[] data,
                            out byte[] signature)
    {
        Utils.ExtractMechanismType(mechanismType, out CKM hashMechanismType, out CKM signMechanismType, out string hashAlgorithmOid);
        using var hashMechanism = session.Factories.MechanismFactory.Create(hashMechanismType);
        var digest = session.Digest(hashMechanism, data);

        switch (signMechanismType)
        {
            case CKM.CKM_RSA_PKCS:
                var digestInfo = Utils.CreateDigestInfo(digest, hashAlgorithmOid);
                using (var rsaSignMechanism = session.Factories.MechanismFactory.Create(signMechanismType))
                {
                    signature = session.Sign(rsaSignMechanism, privKeyHandle, digestInfo);
                }
                break;
            case CKM.CKM_RSA_PKCS_PSS:
                var pssMechanismParams = Utils.CreateCkRsaPkcsPssParams(session, hashMechanismType);
                using (IMechanism mechanism = session.Factories.MechanismFactory.Create(signMechanismType, pssMechanismParams))
                {
                    signature = session.Sign(mechanism, privKeyHandle, digest);
                }
                break;
            case CKM.CKM_ECDSA:
                using (var ecSignMechanism = session.Factories.MechanismFactory.Create(signMechanismType))
                {
                    var ecSignature = session.Sign(ecSignMechanism, privKeyHandle, digest);
                    signature = Utils.EncodeToAsn1DerSignature(ecSignature);
                }
                break;
            default:
                signature = [];
                break;
        }
    }

    public static void Verify(ISession session,
                              byte[] data,
                              byte[] signature,
                              CKM mechanismType,
                              IObjectHandle publicKey,
                              out bool isValid)
    {
        var signer = Utils.GetSigner(mechanismType, out CKM signMechanismType);

        switch (signMechanismType)
        {
            case CKM.CKM_RSA_PKCS:
            case CKM.CKM_RSA_PKCS_PSS:
                var rsaPublicKeyParameters = Utils.GetRsaPublicKeyParams(session, publicKey, out _);
                signer.Init(false, rsaPublicKeyParameters);
                signer.BlockUpdate(data, 0, data.Length);
                isValid = signer.VerifySignature(signature);
                break;
            case CKM.CKM_ECDSA:
                var ecPublicKeyParameters = Utils.GetEcPublicKeyParams(session, publicKey, out _);
                signer.Init(false, ecPublicKeyParameters);
                signer.BlockUpdate(data, 0, data.Length);
                isValid = signer.VerifySignature(signature);
                break;
            default:
                isValid = false;
                break;
        }
    }

    public static void SignCms(ISession session,
                               IObjectHandle privKeyHandle,
                               X509Certificate2 certificate,
                               IEnumerable<X509Certificate2> chain,
                               CKM mechanismType,
                               bool detached,
                               byte[] data,
                               out byte[] signature)
    {
        Utils.ExtractMechanismType(mechanismType, out CKM hashMechanismType, out CKM signMechanismType, out string hashAlgorithmOid);
        using var hashMechanism = session.Factories.MechanismFactory.Create(hashMechanismType);
        var digest = session.Digest(hashMechanism, data);

        // Construct SignerInfo.signedAttrs
        var signedAttributesVector = new Asn1EncodableVector
        {
            // Add PKCS#9 contentType signed attribute
            new Attribute(
                attrType: new DerObjectIdentifier(Oids.ContentType),
                attrValues: new DerSet(new DerObjectIdentifier(Oids.Pkcs7Data))),

            // Add PKCS#9 messageDigest signed attribute
            new Attribute(
                attrType: new DerObjectIdentifier(Oids.MessageDigest),
                attrValues: new DerSet(new DerOctetString(digest))),

            // Add PKCS#9 signingTime signed attribute
            new Attribute(
                attrType: new DerObjectIdentifier(Oids.SigningTime),
                attrValues: new DerSet(new Time(new DerUtcTime(DateTime.UtcNow, DateTime.UtcNow.Year + 99))))
        };

        // Compute digest of SignerInfo.signedAttrs
        var signedAttributes = new DerSet(signedAttributesVector);
        var signedAttributesDigest = session.Digest(hashMechanism, signedAttributes.GetDerEncoded());

        // Sign digest of SignerInfo.signedAttrs with private key stored on PKCS#11 compatible device
        Asn1OctetString digestSignature;
        AlgorithmIdentifier digestSignatureAlgorithm;

        switch (signMechanismType)
        {
            case CKM.CKM_RSA_PKCS:
                var digestInfo = Utils.CreateDigestInfo(digest, hashAlgorithmOid);
                using (var rsaSignMechanism = session.Factories.MechanismFactory.Create(signMechanismType))
                {
                    signature = session.Sign(rsaSignMechanism, privKeyHandle, digestInfo);
                }
                // Construct SignerInfo.signature
                digestSignature = new DerOctetString(signature);
                // Construct SignerInfo.signatureAlgorithm
                digestSignatureAlgorithm = new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(Oids.Rsa),
                    parameters: DerNull.Instance
                );
                break;
            case CKM.CKM_RSA_PKCS_PSS:
                var pssMechanismParams = Utils.CreateCkRsaPkcsPssParams(session, hashMechanismType);
                using (IMechanism mechanism = session.Factories.MechanismFactory.Create(signMechanismType, pssMechanismParams))
                {
                    signature = session.Sign(mechanism, privKeyHandle, digest);
                }
                // Construct SignerInfo.signature
                digestSignature = new DerOctetString(signature);
                // Construct SignerInfo.signatureAlgorithm
                digestSignatureAlgorithm = new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(Oids.RsaPss),
                    parameters: new RsassaPssParameters(
                        hashAlgorithm: new AlgorithmIdentifier(
                            algorithm: new DerObjectIdentifier(hashAlgorithmOid),
                            parameters: DerNull.Instance
                        ),
                        maskGenAlgorithm: new AlgorithmIdentifier(
                            algorithm: new DerObjectIdentifier(Oids.Mgf1),
                            parameters: new AlgorithmIdentifier(
                                algorithm: new DerObjectIdentifier(hashAlgorithmOid),
                                parameters: DerNull.Instance
                            )
                        ),
                        saltLength: new DerInteger(Utils.GetDigestSize(hashMechanismType)),
                        trailerField: new DerInteger(1)
                    )
                );
                break;
            case CKM.CKM_ECDSA:
                using (var ecSignMechanism = session.Factories.MechanismFactory.Create(signMechanismType))
                {
                    var ecSignature = session.Sign(ecSignMechanism, privKeyHandle, digest);
                    signature = Utils.EncodeToAsn1DerSignature(ecSignature);
                }
                // Construct SignerInfo.signature
                digestSignature = new DerOctetString(signature);
                // Construct SignerInfo.signatureAlgorithm
                digestSignatureAlgorithm = new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(Oids.ECDsa),
                    parameters: DerNull.Instance
                );
                break;
            default:
                throw new CryptographicException(NotSupportedKeyAlgorithm);
        }

        var signingCertificate = DotNetUtilities.FromX509Certificate(certificate);
        // Construct SignerInfo
        var signerInfo = new SignerInfo(
            sid: new SignerIdentifier(new IssuerAndSerialNumber(signingCertificate.IssuerDN, signingCertificate.SerialNumber)),
            digAlgorithm: new AlgorithmIdentifier(
                algorithm: new DerObjectIdentifier(hashAlgorithmOid),
                parameters: DerNull.Instance
            ),
            authenticatedAttributes: signedAttributes,
            digEncryptionAlgorithm: digestSignatureAlgorithm,
            encryptedDigest: digestSignature,
            unauthenticatedAttributes: null
        );

        // Construct SignedData.digestAlgorithms
        var digestAlgorithmsVector = new Asn1EncodableVector
        {
            new AlgorithmIdentifier(
                algorithm: new DerObjectIdentifier(hashAlgorithmOid),
                parameters: DerNull.Instance)
        };

        // Construct SignedData.encapContentInfo
        var encapContentInfo = new ContentInfo(
            contentType: new DerObjectIdentifier(Oids.Pkcs7Data),
            content: (detached) ? null : new DerOctetString(data));

        // Construct SignedData.certificates
        var certificatesVector = new Asn1EncodableVector();
        foreach (var cert in chain)
        {
            certificatesVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.RawData)));
        }

        // Construct SignedData.signerInfos
        var signerInfosVector = new Asn1EncodableVector
        {
            signerInfo.ToAsn1Object()
        };

        // Construct SignedData
        var signedData = new SignedData(
            digestAlgorithms: new DerSet(digestAlgorithmsVector),
            contentInfo: encapContentInfo,
            certificates: new BerSet(certificatesVector),
            crls: null,
            signerInfos: new DerSet(signerInfosVector));

        // Construct top level ContentInfo
        var contentInfo = new ContentInfo(
            contentType: new DerObjectIdentifier(Oids.Pkcs7Signed),
            content: signedData);

        signature = contentInfo.GetDerEncoded();
    }

    /// <summary>
    /// Verifies the digital signatures on the signed CMS/PKCS#7 message.
    /// </summary>
    /// <param name="attachedMessage">The encoded message received from the sender.</param>
    /// <param name="validateCertificate">A Boolean value that specifies whether to check the validity of the signer's certificate.</param>
    /// <param name="chain">An X509Certificate2 collection that can be used to validate the certificate chain.</param>
    /// <returns>A <see cref="VerificationResult{T}"/> that returns the signature verification result, the unsigned original content, and the signers' certificates.</returns>
    public void VerifyCms(out byte[] originalContent,
                                 out IEnumerable<X509Certificate2> signerCertificates,
                                 out bool isValid,
                                 byte[] attachedMessage,
                                 bool validateCertificate = true,
                                 IEnumerable<X509Certificate2>? chain = null)
    {
        try
        {
            var signedCms = new SignedCms();
            signedCms.Decode(attachedMessage);
            if (chain != null)
                signedCms.CheckSignature([.. chain.ToArray()], !validateCertificate);
            else
                signedCms.CheckSignature(!validateCertificate);
            originalContent = signedCms.ContentInfo.Content;

            signerCertificates = signedCms.Certificates;
            //foreach (var signer in signedCms.SignerInfos)
            //{
            //    if (signer.Certificate != null)
            //    {
            //        signerCertificates = signerCertificates.Append(signer.Certificate);
            //    }
            //}

            isValid = true;
        }
        catch (Exception ex)
        {
            originalContent = [];
            signerCertificates = [];
            isValid = false;
            logger?.LogError(ex, "Verify CMS failed.");
        }
    }

    /// <summary>
    /// Verifies the digital signatures on the signed CMS/PKCS#7 message.
    /// </summary>
    /// <param name="originalData">The original message that sent to the signer.</param>
    /// <param name="signedData">The encoded message received from the sender.</param>
    /// <param name="validateCertificate">A Boolean value that specifies whether to check the validity of the signer's certificate.</param>
    /// <param name="chain">An X509Certificate2 collection that can be used to validate the certificate chain.</param>
    /// <returns>A <see cref="VerificationResult{T}"/> that returns the signature verification result, the unsigned original content, and the signers' certificates.</returns>
    public  void VerifyCms<T>(out IEnumerable<X509Certificate2> signerCertificates,
                                    out bool isValid,
                                    byte[] originalData,
                                    byte[] signedData,
                                    bool validateCertificate = true,
                                    IEnumerable<X509Certificate2>? chain = null)
    {
        try
        {
            var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(originalData);
            var signedCms = new SignedCms(contentInfo, true);
            signedCms.Decode(signedData);

            if (chain != null)
                signedCms.CheckSignature([.. chain.ToArray()], !validateCertificate);
            else
                signedCms.CheckSignature(!validateCertificate);

            signerCertificates = signedCms.Certificates;
            //foreach (var signer in signedCms.SignerInfos)
            //{
            //    if (signer.Certificate != null)
            //    {
            //        signerCertificates = signerCertificates.Append(signer.Certificate);
            //    }
            //}

            isValid = true;
        }
        catch (Exception ex)
        {
            signerCertificates = [];
            isValid = false;
            logger?.LogError(ex, "Verify CMS failed.");
        }
    }

    public static void SignEncrypt(ISession session,
                                   IObjectHandle privKeyHandle,
                                   CKM signMechanismType,
                                   IObjectHandle encryptKeyHandle,
                                   CKM encMechanismType,
                                   CKM? hashMechanismType,
                                   byte[] data,
                                   out byte[] signature,
                                   out byte[] encryptedData)
    {
        using IMechanism encryptionMechanism = session.Factories.MechanismFactory.Create(encMechanismType);

        switch (signMechanismType)
        {
            case CKM.CKM_RSA_PKCS:
                using (var rsaSignMechanism = session.Factories.MechanismFactory.Create(signMechanismType))
                {
                    session.SignEncrypt(rsaSignMechanism, privKeyHandle, encryptionMechanism, encryptKeyHandle, data, out signature, out encryptedData);
                }
                break;
            case CKM.CKM_RSA_PKCS_PSS:
                if (hashMechanismType == null)
                    throw new ArgumentNullException(nameof(hashMechanismType));

                var pssMechanismParams = Utils.CreateCkRsaPkcsPssParams(session, hashMechanismType.Value);
                using (IMechanism rsaPssSignMechanism = session.Factories.MechanismFactory.Create(signMechanismType, pssMechanismParams))
                {
                    session.SignEncrypt(rsaPssSignMechanism, privKeyHandle, encryptionMechanism, encryptKeyHandle, data, out signature, out encryptedData);
                }
                break;
            case CKM.CKM_ECDSA:
                using (var ecSignMechanism = session.Factories.MechanismFactory.Create(signMechanismType))
                {
                    session.SignEncrypt(ecSignMechanism, privKeyHandle, encryptionMechanism, encryptKeyHandle, data, out signature, out encryptedData);
                    signature = Utils.EncodeToAsn1DerSignature(signature);
                }
                break;
            default:
                signature = [];
                encryptedData = [];
                break;
        }
    }

    public static void VerifyDecrypt(ISession session,
                                     byte[] data,
                                     byte[] signature,
                                     CKM verificationType,
                                     IObjectHandle publicKey,
                                     CKM decryptionType,
                                     IObjectHandle decryptionKey,
                                     out byte[] decryptedData,
                                     out bool isValid)
    {
        using var verificationMechanism = session.Factories.MechanismFactory.Create(verificationType);
        using var decryptionMechanism = session.Factories.MechanismFactory.Create(decryptionType);

        session.DecryptVerify(verificationMechanism, publicKey, decryptionMechanism, decryptionKey, data, signature, out decryptedData, out isValid);
    }

    public static void SignRecover(ISession session,
                                   IObjectHandle privKeyHandle,
                                   CKM mechanismType,
                                   byte[] data,
                                   out byte[] signature)
    {
        Utils.ExtractMechanismType(mechanismType, out _, out CKM signMechanismType, out _);
        using var mechanism = session.Factories.MechanismFactory.Create(signMechanismType);

        signature = session.SignRecover(mechanism, privKeyHandle, data);
    }

    public static void VerifyRecover(ISession session,
                                     byte[] signature,
                                     CKM mechanismType,
                                     IObjectHandle publicKey,
                                     out bool isValid,
                                     out byte[] recoveredData)
    {
        Utils.ExtractMechanismType(mechanismType, out _, out CKM signMechanismType, out _);
        using var mechanism = session.Factories.MechanismFactory.Create(signMechanismType);
        recoveredData = session.VerifyRecover(mechanism, publicKey, signature, out isValid);
    }
}
