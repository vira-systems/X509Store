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
/// X.509 certificate stored on PKCS#11 token
/// </summary>
public class X509Certificate
{
    /// <summary>
    /// Internal context for Pkcs11X509Certificate2 class
    /// </summary>
    private readonly X509CertificateContext? _certContext;

    private readonly IPKCS11Library _pkcs11Lib;

    /// <summary>
    /// Detailed information about X.509 certificate stored on PKCS#11 token
    /// </summary>
    public X509CertificateInfo Info { get; private set; }

    /// <summary>
    /// Flag indicating whether private key object corresponding to certificate object was found on token
    /// </summary>
    public bool HasPrivateKeyObject { get; private set; }

    /// <summary>
    /// Flag indicating whether public key object corresponding to certificate object was found on token
    /// </summary>
    public bool HasPublicKeyObject { get; private set; }

    public X509Certificate(X509Certificate2 certificate, IPKCS11Library pkcs11Lib)
    {
        _pkcs11Lib = pkcs11Lib;
        HasPrivateKeyObject = certificate.HasPrivateKey;
        HasPublicKeyObject = certificate.PublicKey != null;
        Info = new X509CertificateInfo(certificate.Thumbprint, certificate.FriendlyName, certificate.RawData);
    }

    /// <summary>
    /// Creates new instance of Pkcs11X509Certificate2 class
    /// </summary>
    /// <param name="certHandle">High level PKCS#11 object handle of certificate object</param>
    /// <param name="tokenContext">Internal context for Pkcs11Token class</param>
    internal X509Certificate(IObjectHandle certHandle, TokenContext tokenContext, IPKCS11Library pkcs11Lib)
    {
        ArgumentNullException.ThrowIfNull(certHandle);
        ArgumentNullException.ThrowIfNull(tokenContext);

        _pkcs11Lib = pkcs11Lib;
        _certContext = GetCertificateContext(certHandle, tokenContext);
        HasPrivateKeyObject = _certContext.PrivKeyHandle != null;
        HasPublicKeyObject = _certContext.PubKeyHandle != null;
        Info = _certContext.CertificateInfo;
    }

    /// <summary>
    /// Constructs internal context for Pkcs11X509Certificate class
    /// </summary>
    /// <param name="certHandle">High level PKCS#11 object handle of certificate object</param>
    /// <param name="tokenContext">Internal context for Pkcs11Token class</param>
    /// <returns>Internal context for Pkcs11X509Certificate class</returns>
    private static X509CertificateContext GetCertificateContext(IObjectHandle certHandle, TokenContext tokenContext)
    {
        using ISession session = tokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly);
        List<IObjectAttribute> objectAttributes = session.GetAttributeValue(certHandle, [CKA.CKA_ID, CKA.CKA_LABEL, CKA.CKA_VALUE]);

        byte[] ckaId = objectAttributes[0].GetValueAsByteArray();
        string ckaLabel;
        try
        {
            ckaLabel = objectAttributes[1].GetValueAsString();
        }
        catch //(Exception ex)
        {
            ckaLabel = "Unknown";
        }
        byte[] ckaValue = objectAttributes[2].GetValueAsByteArray();

        var certInfo = new X509CertificateInfo(Convert.ToHexString(ckaId), ckaLabel, ckaValue);

        var privKeyHandle = KeyUtils.FindKey(session, CKO.CKO_PRIVATE_KEY, ckaId);
        var pubKeyHandle = KeyUtils.FindKey(session, CKO.CKO_PUBLIC_KEY, ckaId);

        bool keyUsageRequiresLogin = privKeyHandle != null && KeyUtils.GetCkaAlwaysAuthenticateValue(session, privKeyHandle);

        return new X509CertificateContext(certInfo, certHandle, privKeyHandle, pubKeyHandle, keyUsageRequiresLogin, tokenContext);
    }

    ///// <summary>
    ///// Gets value of CKA_ALWAYS_AUTHENTICATE attribute of private key object
    ///// </summary>
    ///// <param name="session">PKCS#11 session for finding operation</param>
    ///// <param name="privKeyHandle">Handle of private key object</param>
    ///// <returns>Value of CKA_ALWAYS_AUTHENTICATE</returns>
    //private bool GetCkaAlwaysAuthenticateValue(ISession session, IObjectHandle privKeyHandle)
    //{
    //    try
    //    {
    //        List<IObjectAttribute> objectAttributes = session.GetAttributeValue(privKeyHandle, [CKA.CKA_ALWAYS_AUTHENTICATE]);
    //        return objectAttributes[0].GetValueAsBool();
    //    }
    //    catch
    //    {
    //        // When CKA_ALWAYS_AUTHENTICATE cannot be read we can assume its value is CK_FALSE
    //        return false;
    //    }
    //}

    ///// <summary>
    ///// Finds handle of key object present on token
    ///// </summary>
    ///// <param name="session">PKCS#11 session for finding operation</param>
    ///// <param name="keyClass">Value of CKA_CLASS attribute used in search template</param>
    ///// <param name="ckaId">Value of CKA_ID attribute used in search template</param>
    ///// <returns>Handle of key object present on token or null</returns>
    //private IObjectHandle FindKey(ISession session, CKO keyClass, byte[] ckaId)
    //{
    //    IObjectHandle keyHandle = null;

    //    var searchTemplate = new List<IObjectAttribute>()
    //    {
    //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, keyClass),
    //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
    //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId),
    //    };

    //    foreach (IObjectHandle foundObjectHandle in session.FindAllObjects(searchTemplate))
    //    {
    //        keyHandle = foundObjectHandle;
    //        break;
    //    }

    //    return keyHandle;
    //}

    ///// <summary>
    ///// Gets PKCS#11 based implementation of the RSA algorithm
    ///// </summary>
    ///// <returns>PKCS#11 RSA provider or null if RSA is not present on token</returns>
    //public RsaProvider? GetRsaProvider(byte[] ckaId)
    //{
    //    if (_certContext.CertificateInfo.KeyType != AsymmetricKeyType.RSA)
    //        return null;

    //    return new RsaProvider(_certContext, ckaId);
    //}

    /// <summary>
    /// Gets the System.Security.Cryptography.RSA implementation for private key
    /// </summary>
    /// <returns>System.Security.Cryptography.RSA implementation for private key or null if RSA private key is not present on token</returns>
    public RSA? GetRSAPrivateKey()
    {
        if (_certContext?.CertificateInfo.KeyType != AsymmetricKeyType.RSA)
            return null;
        if (!HasPrivateKeyObject && string.IsNullOrEmpty(Info.Id))
            return null;

        return new RsaProvider(_pkcs11Lib, _certContext, Convert.FromHexString(Info.Id));
    }

    /// <summary>
    /// Gets the System.Security.Cryptography.RSA implementation for public key
    /// </summary>
    /// <returns>System.Security.Cryptography.RSA implementation for public key or null if RSA public key is not present on token</returns>
    public RSA? GetRSAPublicKey()
    {
        if (_certContext?.CertificateInfo.KeyType != AsymmetricKeyType.RSA || !HasPublicKeyObject)
            return null;

        return new RsaProvider(_pkcs11Lib, _certContext);
    }

    ///// <summary>
    ///// Gets PKCS#11 based implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA)
    ///// </summary>
    ///// <returns>PKCS#11 ECDsa provider or null if ECDsa is not present on token</returns>
    //public ECDsaProvider? GetECDsaProvider(byte[]? ckaId = null)
    //{
    //    if (_certContext.CertificateInfo.KeyType != AsymmetricKeyType.EC)
    //        return null;
    //    if (!HasPrivateKeyObject && ckaId == null)
    //        return null;

    //    return new ECDsaProvider(_certContext, ckaId);
    //}

    /// <summary>
    /// Gets the System.Security.Cryptography.ECDsa implementation for private key
    /// </summary>
    /// <returns>System.Security.Cryptography.ECDsa implementation for private key or null if ECDsa private key is not present on token</returns>
    public ECDsa? GetECDsaPrivateKey()
    {
        if (_certContext?.CertificateInfo.KeyType != AsymmetricKeyType.EC)
            return null;
        if (!HasPrivateKeyObject && string.IsNullOrEmpty(Info.Id))
            return null;

        return new ECDsaProvider(_pkcs11Lib, _certContext, Convert.FromHexString(Info.Id));
    }

    /// <summary>
    /// Gets the System.Security.Cryptography.ECDsa implementation for public key
    /// </summary>
    /// <returns>System.Security.Cryptography.ECDsa implementation for public key or null if ECDsa public key is not present on token</returns>
    public ECDsa? GetECDsaPublicKey()
    {
        if (_certContext?.CertificateInfo.KeyType != AsymmetricKeyType.EC || !HasPublicKeyObject)
            return null;

        return new ECDsaProvider(_pkcs11Lib, _certContext);
    }

    /// <summary>
    /// Gets the System.Security.Cryptography.AsymmetricAlgorithm implementation for private key
    /// </summary>
    /// <returns>System.Security.Cryptography.AsymmetricAlgorithm implementation for private key or null if private key is not present on token</returns>
    public AsymmetricAlgorithm? GetPrivateKey()
    {
        return _certContext?.CertificateInfo.KeyType switch
        {
            AsymmetricKeyType.RSA => GetRSAPrivateKey(),
            AsymmetricKeyType.EC => GetECDsaPrivateKey(),
            _ => null,
        };
    }

    /// <summary>
    /// Gets the System.Security.Cryptography.AsymmetricAlgorithm implementation for public key
    /// </summary>
    /// <returns>System.Security.Cryptography.AsymmetricAlgorithm implementation for public key or null if public key is not present on token</returns>
    public AsymmetricAlgorithm? GetPublicKey()
    {
        return _certContext?.CertificateInfo.KeyType switch
        {
            AsymmetricKeyType.RSA => GetRSAPublicKey(),
            AsymmetricKeyType.EC => GetECDsaPublicKey(),
            _ => null,
        };
    }
}
