/*
 *  Copyright 2017-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// PKCS#11 based implementation of the RSA algorithm
/// </summary>
public class RsaProvider : RSA
{
    /// <summary>
    /// Internal context for Pkcs11X509Certificate2 class
    /// </summary>
    private readonly X509CertificateContext _certContext;
    private readonly ISlot _slot;
    private readonly bool _keyUsageRequiresLogin;
    private readonly IPKCS11Library _pkcs11Lib;

    /// <summary>
    /// Creates new instance of Pkcs11RsaProvider class
    /// </summary>
    /// <param name="certContext">Internal context for Pkcs11X509Certificate2 class</param>
    internal RsaProvider(IPKCS11Library pkcs11Lib, X509CertificateContext certContext, byte[]? ckaId = null)
    {
        _pkcs11Lib = pkcs11Lib;
        _certContext = certContext; //?? throw new ArgumentNullException(nameof(certContext));

        var rsaPubKey = _certContext.CertificateInfo.ParsedCertificate.GetRSAPublicKey()
            ?? throw new InvalidOperationException("The certificate is not RSA.");
        KeySizeValue = rsaPubKey.KeySize;
        LegalKeySizesValue = [new KeySizes(KeySizeValue, KeySizeValue, 0)];

        _slot = _certContext.TokenContext.SlotContext.Slot;
        var session = _certContext.TokenContext.SlotContext.Session;

        if (_certContext.PubKeyHandle == null)
        {
            if (ckaId != null)
                _certContext.PubKeyHandle = KeyUtils.FindKey(session, CKO.CKO_PUBLIC_KEY, ckaId);
            else
                throw new InvalidOperationException("The public key handle not found.");
        }

        if (_certContext.PrivKeyHandle == null && ckaId != null)
        {
            _certContext.PrivKeyHandle = KeyUtils.FindKey(session, CKO.CKO_PRIVATE_KEY, ckaId);
        }

        _keyUsageRequiresLogin = KeyUtils.GetCkaAlwaysAuthenticateValue(session, _certContext.PrivKeyHandle!);
    }

    //internal RsaProvider(KeyInfo pubKeyInfo, KeyInfo prvKeyInfo, int keySize)
    //{
    //    var certificateInfo = new X509CertificateInfo(pubKeyInfo.CkaId, pubKeyInfo.CkaLabel, []);
    //    _certContext = new X509CertificateContext(certificateInfo, prvKeyInfo.ObjectHandle, prvKeyInfo.ObjectHandle, pubKeyInfo.ObjectHandle, false, PKCS11Library.Instance.Token!.TokenContext);
    //    KeySizeValue = keySize; // (int)pubKeyInfo.StorageSize;
    //    LegalKeySizesValue = [new KeySizes(KeySizeValue, KeySizeValue, 0)];

    //    _slot = _certContext.TokenContext.SlotContext.Slot;
    //    var session = _certContext.TokenContext.SlotContext.Session;
    //    _keyUsageRequiresLogin = KeyUtils.GetCkaAlwaysAuthenticateValue(session, prvKeyInfo.ObjectHandle);
    //}

    //public void CmsSign(ISession session, byte[] data, bool detached, out byte[] signature)
    //{
    //    try
    //    {
    //        if (_certContext.PrivKeyHandle == null)
    //            throw new PrivateKeyObjectNotFoundException();

    //        var x509Certificate = _certContext.CertificateInfo.ParsedCertificate;
    //        var x509chain = new X509Chain();
    //        x509chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
    //        x509chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    //        if (x509chain.Build(x509Certificate))
    //        {
    //            var chain = x509chain.ChainElements
    //                //.Where(e => !e.Certificate.Thumbprint.Equals(x509Certificate.Thumbprint))
    //                .Select(e => e.Certificate)
    //                .ToArray();
    //            PKCS11Library.SignCms(session,
    //                                  _certContext.PrivKeyHandle,
    //                                  x509Certificate,
    //                                  chain,
    //                                  CKM.CKM_SHA256_RSA_PKCS,
    //                                  detached,
    //                                  data,
    //                                  out signature);
    //        }
    //        else
    //        {
    //            PKCS11Library.SignCms(session,
    //                                  _certContext.PrivKeyHandle,
    //                                  x509Certificate,
    //                                  [],
    //                                  CKM.CKM_SHA256_RSA_PKCS,
    //                                  detached,
    //                                  data,
    //                                  out signature);
    //        }
    //    }
    //    catch (Exception ex)
    //    {

    //        throw;
    //    }
    //}

    /// <summary>
    /// Computes the signature for the specified hash value by encrypting it with the private key using the specified padding
    /// </summary>
    /// <param name="hash">The hash value of the data to be signed</param>
    /// <param name="hashAlgorithm">The hash algorithm used to create the hash value of the data</param>
    /// <param name="padding">The padding</param>
    /// <returns>The RSA signature for the specified hash value</returns>
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (hash == null || hash.Length == 0)
            throw new ArgumentNullException(nameof(hash));

        //if (hashAlgorithm == null)
        //    throw new ArgumentNullException(nameof(hashAlgorithm));

        //if (padding == null)
        //    throw new ArgumentNullException(nameof(padding));

        ArgumentNullException.ThrowIfNull(padding, nameof(padding));

        if (_certContext.PrivKeyHandle == null)
            throw new PrivateKeyObjectNotFoundException();

        if (padding == RSASignaturePadding.Pkcs1)
        {
            byte[] pkcs1DigestInfo = CreatePkcs1DigestInfo(hash, hashAlgorithm)
                ?? throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            
            if (_keyUsageRequiresLogin)
            {
                var pinResult = _pkcs11Lib.RequestKeyPinAsync().GetAwaiter().GetResult();
                return session.Sign(mechanism, _certContext.PrivKeyHandle, pinResult.Pin, pkcs1DigestInfo);
                //return session.Sign(mechanism, _privateKeyHandle, PinProviderUtils.GetKeyPin(_pinProvider), pkcs1DigestInfo);
            }
            else
            {
                return session.Sign(mechanism, _certContext.PrivKeyHandle, pkcs1DigestInfo);
            }
        }
        else if (padding == RSASignaturePadding.Pss)
        {
            IMechanismParamsFactory mechanismParamsFactory = _slot.Factories.MechanismParamsFactory;

            ICkRsaPkcsPssParams pssMechanismParams = CreateCkRsaPkcsPssParams(mechanismParamsFactory, hash, hashAlgorithm)
                ?? throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_PSS, pssMechanismParams);
            
            if (_keyUsageRequiresLogin)
            {
                var pinResult = _pkcs11Lib.RequestKeyPinAsync().GetAwaiter().GetResult();
                return session.Sign(mechanism, _certContext.PrivKeyHandle, pinResult.Pin, hash);
                //return session.Sign(mechanism, _privateKeyHandle, PinProviderUtils.GetKeyPin(_pinProvider), hash);
            }
            else
            {
                return session.Sign(mechanism, _certContext.PrivKeyHandle, hash);
            }
        }
        else
        {
            throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));
        }
    }

    /// <summary>
    /// Verifies that a digital signature is valid by determining the hash value in the signature using the specified hash algorithm and padding, and comparing it to the provided hash value
    /// </summary>
    /// <param name="hash">he hash value of the signed data</param>
    /// <param name="signature">The signature data to be verified</param>
    /// <param name="hashAlgorithm">The hash algorithm used to create the hash value</param>
    /// <param name="padding">The padding mode</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (hash == null || hash.Length == 0)
            throw new ArgumentNullException(nameof(hash));

        if (signature == null || signature.Length == 0)
            throw new ArgumentNullException(nameof(signature));

        //if (hashAlgorithm == null)
        //    throw new ArgumentNullException(nameof(hashAlgorithm));

        //if (padding == null)
        //    throw new ArgumentNullException(nameof(padding));

        ArgumentNullException.ThrowIfNull(padding, nameof(padding));

        if (_certContext?.PubKeyHandle == null)
            throw new PublicKeyObjectNotFoundException();

        if (padding == RSASignaturePadding.Pkcs1)
        {
            byte[] pkcs1DigestInfo = CreatePkcs1DigestInfo(hash, hashAlgorithm)
                ?? throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm));

            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            session.Verify(mechanism, _certContext.PubKeyHandle, pkcs1DigestInfo, signature, out bool isValid);
            
            return isValid;
        }
        else if (padding == RSASignaturePadding.Pss)
        {
            IMechanismParamsFactory mechanismParamsFactory = _slot.Factories.MechanismParamsFactory;

            ICkRsaPkcsPssParams pssMechanismParams = CreateCkRsaPkcsPssParams(mechanismParamsFactory, hash, hashAlgorithm)
                ?? throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_PSS, pssMechanismParams);
            session.Verify(mechanism, _certContext.PubKeyHandle, hash, signature, out bool isValid);
            
            return isValid;
        }
        else
        {
            throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));
        }
    }

    /// <summary>
    /// Decrypts the input data using the specified padding mode
    /// </summary>
    /// <param name="data">The data to decrypt</param>
    /// <param name="padding">The padding mode</param>
    /// <returns>The decrypted data</returns>
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentNullException(nameof(data));

        //if (padding == null)
        //    throw new ArgumentNullException(nameof(padding));

        ArgumentNullException.ThrowIfNull(padding, nameof(padding));

        if (_certContext?.PrivKeyHandle == null)
            throw new PrivateKeyObjectNotFoundException();

        if (padding == RSAEncryptionPadding.Pkcs1)
        {
            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            
            if (_keyUsageRequiresLogin)
                throw new NotSupportedException("Decryption with key that requires context specific login to be performed is not supported");
            else
                return session.Decrypt(mechanism, _certContext.PrivKeyHandle, data);
        }
        else if (padding == RSAEncryptionPadding.OaepSHA1 ||
                 padding == RSAEncryptionPadding.OaepSHA256 ||
                 padding == RSAEncryptionPadding.OaepSHA384 ||
                 padding == RSAEncryptionPadding.OaepSHA512)
        {
            IMechanismParamsFactory mechanismParamsFactory = _slot.Factories.MechanismParamsFactory;

            ICkRsaPkcsOaepParams oaepMechanismParams = CreateCkRsaPkcsOaepParams(mechanismParamsFactory, padding)
                ?? throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));

            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_OAEP, oaepMechanismParams);
            
            if (_keyUsageRequiresLogin)
                throw new NotSupportedException("Decryption with key that requires context specific login to be performed is not supported");
            else
                return session.Decrypt(mechanism, _certContext.PrivKeyHandle, data);
        }
        else
        {
            throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));
        }
    }

    /// <summary>
    /// Encrypts the input data using the specified padding mode
    /// </summary>
    /// <param name="data">The data to encrypt</param>
    /// <param name="padding">The padding mode</param>
    /// <returns>The encrypted data</returns>
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentNullException(nameof(data));

        //if (padding == null)
        //    throw new ArgumentNullException(nameof(padding));

        ArgumentNullException.ThrowIfNull(padding, nameof(padding));

        if (_certContext?.PubKeyHandle == null)
            throw new PublicKeyObjectNotFoundException();

        if (padding == RSAEncryptionPadding.Pkcs1)
        {
            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            
            return session.Encrypt(mechanism, _certContext.PubKeyHandle, data);
        }
        else if (padding == RSAEncryptionPadding.OaepSHA1 ||
                 padding == RSAEncryptionPadding.OaepSHA256 ||
                 padding == RSAEncryptionPadding.OaepSHA384 ||
                 padding == RSAEncryptionPadding.OaepSHA512)
                 //padding == RSAEncryptionPadding.OaepSHA3_256 ||
                 //padding == RSAEncryptionPadding.OaepSHA3_384 ||
                 //padding == RSAEncryptionPadding.OaepSHA3_512)
        {
            IMechanismParamsFactory mechanismParamsFactory = _slot.Factories.MechanismParamsFactory;

            ICkRsaPkcsOaepParams oaepMechanismParams = CreateCkRsaPkcsOaepParams(mechanismParamsFactory, padding)
                ?? throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));

            using ISession session = _slot.OpenSession(SessionType.ReadOnly);
            using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_OAEP, oaepMechanismParams);
            
            return session.Encrypt(mechanism, _certContext.PubKeyHandle, data);
        }
        else
        {
            throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));
        }
    }

    ///// <summary>
    ///// Decrypts the input data using the private key
    ///// </summary>
    ///// <param name="rgb">The cipher text to be decrypted</param>
    ///// <returns>The resulting decryption of the rgb parameter in plain text</returns>
    //public override byte[] DecryptValue(byte[] rgb)
    //{
    //    // Note: NotSupportedException should be thrown starting with the .NET Framework 4.6.
    //    throw new NotSupportedException();
    //}

    ///// <summary>
    ///// Encrypts the input data using the public key
    ///// </summary>
    ///// <param name="rgb">The plain text to be encrypted</param>
    ///// <returns>The resulting encryption of the rgb parameter as cipher text</returns>
    //public override byte[] EncryptValue(byte[] rgb)
    //{
    //    // Note: NotSupportedException should be thrown starting with the .NET Framework 4.6.
    //    throw new NotSupportedException();
    //}

    /// <summary>
    /// Computes the hash value of a specified portion of a byte array by using a specified hashing algorithm
    /// </summary>
    /// <param name="data">The data to be hashed</param>
    /// <param name="offset">The index of the first byte in data that is to be hashed</param>
    /// <param name="count">The number of bytes to hash</param>
    /// <param name="hashAlgorithm">The algorithm to use in hash the data</param>
    /// <returns>The hashed data</returns>
    protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentNullException(nameof(data));

        if (offset < 0 || offset >= data.Length)
            throw new ArgumentException($"Invalid value of {nameof(offset)} parameter");

        if (count < 1 || offset + count > data.Length)
            throw new ArgumentException($"Invalid value of {nameof(count)} parameter");

        //if (hashAlgorithm == null)
        //    throw new ArgumentNullException(nameof(hashAlgorithm));

        //using var hashAlg = HashAlgorithm.Create(hashAlgorithm.Name);
        //return hashAlg.ComputeHash(data, offset, count);

        var source = data
            .Take(new Range(offset, offset + count))
            .ToArray();

        return hashAlgorithm.Name switch
        {
            "MD5" => MD5.HashData(source),
            "SHA1" => SHA1.HashData(source),
            "SHA256" => SHA256.HashData(source),
            "SHA384" => SHA384.HashData(source),
            "SHA512" => SHA512.HashData(source),
            "SHA3-256" => SHA3_256.HashData(source),
            "SHA3-384" => SHA3_384.HashData(source),
            "SHA3-512" => SHA3_512.HashData(source),
            _ => throw new NotSupportedException("The hash algorithm is not supported."),
        };
    }

    /// <summary>
    /// Computes the hash value of a specified binary stream by using a specified hashing algorithm
    /// </summary>
    /// <param name="data">The binary stream to hash</param>
    /// <param name="hashAlgorithm">The hash algorithm</param>
    /// <returns>The hashed data</returns>
    protected override byte[] HashData(Stream stream, HashAlgorithmName hashAlgorithm)
    {
        //if (stream == null)
        //    throw new ArgumentNullException(nameof(stream));

        //if (hashAlgorithm == null)
        //    throw new ArgumentNullException(nameof(hashAlgorithm));

        //using var hashAlg = HashAlgorithm.Create(hashAlgorithm.Name);
        //return hashAlg.ComputeHash(data);

        // Note: data.Length might throw NotSupportedException
        ArgumentNullException.ThrowIfNull(stream, nameof(stream));

        return hashAlgorithm.Name switch
        {
            "MD5" => MD5.HashData(stream),
            "SHA1" => SHA1.HashData(stream),
            "SHA256" => SHA256.HashData(stream),
            "SHA384" => SHA384.HashData(stream),
            "SHA512" => SHA512.HashData(stream),
            "SHA3-256" => SHA3_256.HashData(stream),
            "SHA3-384" => SHA3_384.HashData(stream),
            "SHA3-512" => SHA3_512.HashData(stream),
            _ => throw new NotSupportedException("The hash algorithm is not supported."),
        };
    }

    /// <summary>
    /// Exports the parameters (key) for RSA algorithm
    /// </summary>
    /// <param name="includePrivateParameters">Flag indicating whether to include private parameters</param>
    /// <returns>The parameters (key) for RSA algorithm</returns>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new NotSupportedException("Private key export is not supported");
        if (_certContext == null)
            throw new NotSupportedException("Public key export is not supported when certificate context is null");

        var rsaPubKey = _certContext.CertificateInfo.ParsedCertificate.GetRSAPublicKey() ??
            throw new InvalidCastException("The certificate is not RSA.");

        return rsaPubKey.ExportParameters(false);
    }

    /// <summary>
    /// Imports the parameters (key) for RSA algorithm
    /// </summary>
    /// <param name="parameters">The parameters (key) for RSA algorithm</param>
    public override void ImportParameters(RSAParameters parameters)
    {
        throw new NotSupportedException("Key import is not supported");
    }

    /// <summary>
    /// Creates DER encoded PKCS#1 DigestInfo structure defined in RFC 8017
    /// </summary>
    /// <param name="hash">Hash value</param>
    /// <param name="hashAlgorithm">Hash algorithm</param>
    /// <returns>DER encoded PKCS#1 DigestInfo structure or null</returns>
    private static byte[]? CreatePkcs1DigestInfo(byte[] hash, HashAlgorithmName hashAlgorithm)
    {
        if (hash == null || hash.Length == 0)
            throw new ArgumentNullException(nameof(hash));

        byte[]? pkcs1DigestInfo = null;

        if (hashAlgorithm == HashAlgorithmName.MD5)
        {
            if (hash.Length != 16)
                throw new ArgumentException("Invalid lenght of hash value");

            pkcs1DigestInfo = [0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            if (hash.Length != 20)
                throw new ArgumentException("Invalid lenght of hash value");

            pkcs1DigestInfo = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            if (hash.Length != 32)
                throw new ArgumentException("Invalid lenght of hash value");

            pkcs1DigestInfo = [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            if (hash.Length != 48)
                throw new ArgumentException("Invalid lenght of hash value");

            pkcs1DigestInfo = [0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            if (hash.Length != 64)
                throw new ArgumentException("Invalid lenght of hash value");

            pkcs1DigestInfo = [0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
        }

        return pkcs1DigestInfo;
    }

    /// <summary>
    /// Creates parameters for CKM_RSA_PKCS_PSS mechanism
    /// </summary>
    /// <param name="mechanismParamsFactory">Factory for creation of IMechanismParams instances</param>
    /// <param name="hash">Hash value</param>
    /// <param name="hashAlgorithm">Hash algorithm</param>
    /// <returns>Parameters for CKM_RSA_PKCS_PSS mechanism or null</returns>
    private static ICkRsaPkcsPssParams? CreateCkRsaPkcsPssParams(IMechanismParamsFactory mechanismParamsFactory, byte[] hash, HashAlgorithmName hashAlgorithm)
    {
        if (hash == null || hash.Length == 0)
            throw new ArgumentNullException(nameof(hash));

        ICkRsaPkcsPssParams? pssParams = null;

        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            if (hash.Length != 20)
                throw new ArgumentException("Invalid lenght of hash value");

            pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                hashAlg: (ulong)CKM.CKM_SHA_1,
                mgf: (ulong)CKG.CKG_MGF1_SHA1,
                len: (ulong)hash.Length
            );
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            if (hash.Length != 32)
                throw new ArgumentException("Invalid lenght of hash value");

            pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                hashAlg: (ulong)CKM.CKM_SHA256,
                mgf: (ulong)CKG.CKG_MGF1_SHA256,
                len: (ulong)hash.Length
            );
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            if (hash.Length != 48)
                throw new ArgumentException("Invalid lenght of hash value");

            pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                hashAlg: (ulong)CKM.CKM_SHA384,
                mgf: (ulong)CKG.CKG_MGF1_SHA384,
                len: (ulong)hash.Length
            );
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            if (hash.Length != 64)
                throw new ArgumentException("Invalid lenght of hash value");

            pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                hashAlg: (ulong)CKM.CKM_SHA512,
                mgf: (ulong)CKG.CKG_MGF1_SHA512,
                len: (ulong)hash.Length
            );
        }

        return pssParams;
    }

    /// <summary>
    /// Creates parameters for CKM_RSA_PKCS_OAEP mechanism
    /// </summary>
    /// <param name="mechanismParamsFactory">Factory for creation of IMechanismParams instances</param>
    /// <param name="padding">Padding mode and parameters to use with RSA encryption or decryption operations</param>
    /// <returns>Parameters for CKM_RSA_PKCS_OAEP mechanism or null</returns>
    private static ICkRsaPkcsOaepParams? CreateCkRsaPkcsOaepParams(IMechanismParamsFactory mechanismParamsFactory, RSAEncryptionPadding padding)
    {
        ICkRsaPkcsOaepParams? oaepParams = null;

        if (padding == RSAEncryptionPadding.OaepSHA1)
        {
            oaepParams = mechanismParamsFactory.CreateCkRsaPkcsOaepParams(
                hashAlg: ConvertUtils.UInt64FromCKM(CKM.CKM_SHA_1),
                mgf: ConvertUtils.UInt64FromCKG(CKG.CKG_MGF1_SHA1),
                source: ConvertUtils.UInt64FromUInt32(CKZ.CKZ_DATA_SPECIFIED),
                sourceData: null
            );
        }
        else if (padding == RSAEncryptionPadding.OaepSHA256)
        {
            oaepParams = mechanismParamsFactory.CreateCkRsaPkcsOaepParams(
                hashAlg: ConvertUtils.UInt64FromCKM(CKM.CKM_SHA256),
                mgf: ConvertUtils.UInt64FromCKG(CKG.CKG_MGF1_SHA256),
                source: ConvertUtils.UInt64FromUInt32(CKZ.CKZ_DATA_SPECIFIED),
                sourceData: null
            );
        }
        else if (padding == RSAEncryptionPadding.OaepSHA384)
        {
            oaepParams = mechanismParamsFactory.CreateCkRsaPkcsOaepParams(
                hashAlg: ConvertUtils.UInt64FromCKM(CKM.CKM_SHA384),
                mgf: ConvertUtils.UInt64FromCKG(CKG.CKG_MGF1_SHA384),
                source: ConvertUtils.UInt64FromUInt32(CKZ.CKZ_DATA_SPECIFIED),
                sourceData: null
            );
        }
        else if (padding == RSAEncryptionPadding.OaepSHA512)
        {
            oaepParams = mechanismParamsFactory.CreateCkRsaPkcsOaepParams(
                hashAlg: ConvertUtils.UInt64FromCKM(CKM.CKM_SHA512),
                mgf: ConvertUtils.UInt64FromCKG(CKG.CKG_MGF1_SHA512),
                source: ConvertUtils.UInt64FromUInt32(CKZ.CKZ_DATA_SPECIFIED),
                sourceData: null
            );
        }

        return oaepParams;
    }
}
