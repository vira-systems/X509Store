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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// PKCS#11 based implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA)
/// </summary>
public class ECDsaProvider : ECDsa
{
    private readonly IPKCS11Library _pkcs11Lib;

    /// <summary>
    /// Internal context for Pkcs11X509Certificate2 class
    /// </summary>
    private readonly X509CertificateContext? _certContext = null;

    /// <summary>
    /// Creates new instance of Pkcs11ECDsaProvider class
    /// </summary>
    /// <param name="certContext">Internal context for Pkcs11X509Certificate2 class</param>
    internal ECDsaProvider(IPKCS11Library pkcs11Lib, X509CertificateContext certContext, byte[]? ckaId = null)
    {
        _pkcs11Lib = pkcs11Lib;
        _certContext = certContext ?? throw new ArgumentNullException(nameof(certContext));

        var ecPubKey = _certContext.CertificateInfo.ParsedCertificate.GetECDsaPublicKey()
            ?? throw new InvalidOperationException("The certificate is not ECDsa.");
        KeySizeValue = ecPubKey.KeySize;
        LegalKeySizesValue = [new KeySizes(KeySizeValue, KeySizeValue, 0)];

        var session = certContext.TokenContext.SlotContext.Session;

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
    }

    /// <summary>
    /// Generates a digital signature for the specified hash value
    /// </summary>
    /// <param name="hash">The hash value of the data that is being signed</param>
    /// <returns>A digital signature that consists of the given hash value encrypted with the private key</returns>
    public override byte[] SignHash(byte[] hash)
    {
        if (hash == null || hash.Length == 0)
            throw new ArgumentNullException(nameof(hash));

        if (_certContext?.PrivKeyHandle == null)
            throw new PrivateKeyObjectNotFoundException();

        using ISession session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly);
        using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA);

        if (_certContext.KeyUsageRequiresLogin)
        {
            var pinResult = _pkcs11Lib.RequestKeyPinAsync().GetAwaiter().GetResult();
            return session.Sign(mechanism, _certContext.PrivKeyHandle, pinResult.Pin, hash);
        }
        else
        {
            return session.Sign(mechanism, _certContext.PrivKeyHandle, hash);
        }
    }

    /// <summary>
    /// Verifies a digital signature against the specified hash value
    /// </summary>
    /// <param name="hash">The hash value of a block of data</param>
    /// <param name="signature">The digital signature to be verified</param>
    /// <returns>True if the hash value equals the decrypted signature, false otherwise</returns>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        if (hash == null || hash.Length == 0)
            throw new ArgumentNullException(nameof(hash));

        if (signature == null || signature.Length == 0)
            throw new ArgumentNullException(nameof(signature));
        
        if (_certContext?.PubKeyHandle == null)
            throw new PublicKeyObjectNotFoundException();

        using ISession session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly);
        using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA);
        session.Verify(mechanism, _certContext.PubKeyHandle, hash, signature, out bool isValid);

        return isValid;
    }

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
            .Take(new Range(offset, offset +count))
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
    /// <param name="stream">The binary stream to hash</param>
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
}
