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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Vira.X509Store.Service.Pkcs11;

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
