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
using Vira.X509Store.Service.Pkcs11;
using AlgorithmIdentifier = Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using IssuerAndSerialNumber = Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;
using SignerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo;
using Time = Org.BouncyCastle.Asn1.Cms.Time;

namespace Vira.X509Store.Service;

/// <summary>
/// Static/utility portion of <see cref="PKCS11Library"/> providing low-level PKCS#11 and
/// ASN.1 helpers such as encrypt/decrypt, sign/verify, CSR and CMS construction.
/// </summary>
public partial class PKCS11Library
{
    /// <summary>
    /// Error text for unsupported key algorithm.
    /// </summary>
    private static readonly string NotSupportedKeyAlgorithm = "Key algorithm is not supported.";
    /// <summary>
    /// Error text for unsupported key type.
    /// </summary>
    private static readonly string NotSupportedKeyType = "Key type is not supported.";
    /// <summary>
    /// Error text for unsupported ECDSA key type.
    /// </summary>
    private static readonly string NotSupportedEcKeyType = "ECDsa key type is not supported.";
    /// <summary>
    /// Error text for unsupported RSA key type.
    /// </summary>
    private static readonly string NotSupportedRsaKeyType = "RSA key type is not supported.";

    /// <summary>
    /// Performs digest followed by encrypt in a single token operation.
    /// </summary>
    /// <param name="session">Authenticated PKCS#11 session.</param>
    /// <param name="pubKeyInfo">Public key handle/info.</param>
    /// <param name="digestMechanismType">Digest mechanism (CKM_*) to compute hash.</param>
    /// <param name="encryptionMechanismType">Encryption mechanism (CKM_*) to encrypt data.</param>
    /// <param name="data">Plain data to be digested and encrypted.</param>
    /// <param name="digest">Output computed digest bytes.</param>
    /// <param name="encryptedData">Output encrypted data.</param>
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

    /// <summary>
    /// Performs decrypt followed by digest in a single token operation.
    /// </summary>
    /// <param name="session">Authenticated PKCS#11 session.</param>
    /// <param name="privKeyInfo">Private key handle/info.</param>
    /// <param name="digestMechanismType">Digest mechanism (CKM_*).</param>
    /// <param name="encryptionMechanismType">Decryption mechanism (CKM_*).</param>
    /// <param name="encryptedData">Cipher to decrypt.</param>
    /// <param name="digest">Output digest of decrypted data.</param>
    /// <param name="decryptedData">Output decrypted data.</param>
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

    /// <summary>
    /// Encrypts data using the specified mechanism and public key.
    /// </summary>
    public static void Encrypt(ISession session,
                               KeyInfo pubKeyInfo,
                               CKM mechanismType,
                               byte[] data,
                               out byte[] encryptedData)
    {
        using var mechanism = session.Factories.MechanismFactory.Create(mechanismType);
        encryptedData = session.Encrypt(mechanism, pubKeyInfo.ObjectHandle, data);
    }

    /// <summary>
    /// Decrypts data using the specified mechanism and private key.
    /// </summary>
    public static void Decrypt(ISession session,
                               KeyInfo privKeyInfo,
                               CKM mechanismType,
                               byte[] encryptedData,
                               out byte[] decryptedData)
    {
        using var mechanism = session.Factories.MechanismFactory.Create(mechanismType);
        decryptedData = session.Decrypt(mechanism, privKeyInfo.ObjectHandle, encryptedData);
    }

    /// <summary>
    /// Generates a PEM-encoded PKCS#10 CSR using an existing key pair referenced by handles.
    /// </summary>
    /// <param name="session">Authenticated session.</param>
    /// <param name="keyType">Key type (CKK_RSA/CKK_EC).
    /// </param>
    /// <param name="publicKeyHandle">Handle of the public key object.</param>
    /// <param name="privateKeyHandle">Handle of the private key object.</param>
    /// <param name="subjectDn">Subject distinguished name.</param>
    /// <param name="mechanismType">Signature mechanism for CSR.</param>
    /// <param name="extensions">X.509 extensions to include.</param>
    /// <param name="pkcs10CSR">Output PEM-encoded CSR string.</param>
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

    /// <summary>
    /// Generates a DER-encoded PKCS#10 CSR using the provided key infos (private/public).
    /// </summary>
    /// <param name="session">Authenticated session.</param>
    /// <param name="privKeyInfo">Private key info.</param>
    /// <param name="pubKeyInfo">Public key info.</param>
    /// <param name="subjectDn">Subject distinguished name.</param>
    /// <param name="mechanismType">Signature mechanism for CSR.</param>
    /// <param name="extensions">X.509 extensions to include.</param>
    /// <param name="pkcs10CSR">Output DER-encoded CSR bytes.</param>
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

    /// <summary>
    /// Imports an X509 certificate into the token as a certificate object.
    /// </summary>
    /// <param name="session">Authenticated session.</param>
    /// <param name="certificate">.NET X509 certificate.</param>
    /// <param name="keyId">Associated key identifier (CKA_ID).</param>
    /// <param name="label">Object label to set on the token.</param>
    /// <returns>Handle to the created certificate object.</returns>
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

    /// <summary>
    /// Imports a raw DER certificate into the token as a certificate object.
    /// </summary>
    /// <param name="session">Authenticated session.</param>
    /// <param name="rawData">DER-encoded certificate.</param>
    /// <param name="keyId">Associated key identifier (CKA_ID).</param>
    /// <param name="label">Object label to set on the token.</param>
    /// <returns>Handle to the created certificate object.</returns>
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

    /// <summary>
    /// Computes a digest and signs it using the specified mechanism and private key.
    /// For RSA-PKCS, the DigestInfo is constructed; for ECDSA the signature is converted to DER.
    /// </summary>
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

    /// <summary>
    /// Verifies a signature over data using the specified mechanism and public key.
    /// </summary>
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

    /// <summary>
    /// Builds a CMS/PKCS#7 SignedData message and signs it using a private key on the token.
    /// </summary>
    /// <param name="session">Authenticated session.</param>
    /// <param name="privKeyHandle">Private key handle to sign with.</param>
    /// <param name="certificate">Signer certificate.</param>
    /// <param name="chain">Certificate chain to embed.</param>
    /// <param name="mechanismType">Signing mechanism (CKM_*).</param>
    /// <param name="detached">True for detached signature (no content encapsulated).</param>
    /// <param name="data">Content to sign.</param>
    /// <param name="signature">Output CMS/PKCS#7 bytes.</param>
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
    /// Verifies a signed CMS/PKCS#7 (attached) message and returns content, signer certs and validity.
    /// </summary>
    /// <param name="originalContent">Output original content extracted from message.</param>
    /// <param name="signerCertificates">Output signer certificates.</param>
    /// <param name="isValid">Output flag indicating signature validity.</param>
    /// <param name="attachedMessage">Signed CMS bytes (attached content).</param>
    /// <param name="validateCertificate">Whether to validate certificate chain.</param>
    /// <param name="chain">Optional extra certificates to assist validation.</param>
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
    /// Verifies a signed CMS/PKCS#7 (detached) message and returns signer certs and validity.
    /// </summary>
    /// <param name="signerCertificates">Output signer certificates.</param>
    /// <param name="isValid">Output flag indicating signature validity.</param>
    /// <param name="originalData">Original content that was signed.</param>
    /// <param name="signedData">Detached signature CMS bytes.</param>
    /// <param name="validateCertificate">Whether to validate certificate chain.</param>
    /// <param name="chain">Optional extra certificates to assist validation.</param>
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

    /// <summary>
    /// Signs and encrypts data in a single token operation.
    /// </summary>
    /// <param name="session">Authenticated session.</param>
    /// <param name="privKeyHandle">Private key handle for signing.</param>
    /// <param name="signMechanismType">Signing mechanism (CKM_*).</param>
    /// <param name="encryptKeyHandle">Public/symmetric key handle for encryption.</param>
    /// <param name="encMechanismType">Encryption mechanism (CKM_*).</param>
    /// <param name="hashMechanismType">Optional hash mechanism for RSA-PSS.</param>
    /// <param name="data">Plain data.</param>
    /// <param name="signature">Output signature.</param>
    /// <param name="encryptedData">Output cipher.</param>
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

    /// <summary>
    /// Verifies data and decrypts cipher in a single token operation.
    /// </summary>
    /// <param name="session">Authenticated session.</param>
    /// <param name="data">Plain data to verify against signature.</param>
    /// <param name="signature">Signature bytes.</param>
    /// <param name="verificationType">Verification mechanism (CKM_*).</param>
    /// <param name="publicKey">Public key handle used for verification.</param>
    /// <param name="decryptionType">Decryption mechanism (CKM_*).</param>
    /// <param name="decryptionKey">Private/secret key handle used for decryption.</param>
    /// <param name="decryptedData">Output decrypted data.</param>
    /// <param name="isValid">Output verification result.</param>
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

    /// <summary>
    /// Signs data with recovery (if supported by mechanism) and returns the recovered data.
    /// </summary>
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

    /// <summary>
    /// Verifies signature with recovery (if supported by mechanism) and returns recovered data.
    /// </summary>
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
