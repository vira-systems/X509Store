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

using Microsoft.AspNetCore.SignalR;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Vira.Caching.Services;
using Vira.X509Store.Service.Pkcs11;
using Vira.X509Store.Service.Services;
using CertificateRequest = Vira.X509Store.Service.X509.CertificateRequest;
using X509CertificateStore = System.Security.Cryptography.X509Certificates.X509Store;

namespace Vira.X509Store.Service.Hubs;

/// <summary>
/// SignalR hub exposing PKCS#11 token, user store and cryptographic operations (encryption,
/// decryption, signing, verification, CMS, CSR generation and certificate import/export).
/// Each action returns a <see cref="HubResult{T}"/> through <see cref="ITokenHub"/> callbacks.
/// </summary>
/// <remarks>
/// The hub orchestrates access to: PKCS#11 hardware token (via <see cref="IPKCS11Library"/>),
/// current user certificate store, and combines them for certain queries. Most methods catch
/// exceptions and translate them into failure results to simplify client handling.
/// </remarks>
public class TokenHub(ICertificateProvider certificateProvider, ICacheService cache, IPKCS11Library pkcs11Lib) : Hub<ITokenHub>
{
    /// <summary>
    /// Invoked when a client connects; records a single client connection id for directed PIN prompts.
    /// </summary>
    public override Task OnConnectedAsync()
    {
        cache.Set("SINGLE_CLIENT_ID", Context.ConnectionId);
        //LoadConnectedDevice();
        return base.OnConnectedAsync();
    }

    /// <summary>
    /// Invoked when a client disconnects; removes the tracked connection id.
    /// </summary>
    public override Task OnDisconnectedAsync(Exception? exception)
    {
        cache.Remove("SINGLE_CLIENT_ID");
        return base.OnDisconnectedAsync(exception);
    }

    /// <summary>
    /// Returns service (Windows Service) status to caller.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public Task DastyarStatus()
    {
        var controllers = System.ServiceProcess.ServiceController.GetServices();
        var controller = controllers.SingleOrDefault(svc => svc.ServiceName.Equals("X509 Store", StringComparison.OrdinalIgnoreCase));
        if (controller == null)
        {
            var result = HubResult<SrvStatus>.Success(Hubs.SrvStatus.NotInstalled);
            return Clients.Caller.DastyarStatus(result);
        }

        var status = (SrvStatus)controller.Status;
        return Clients.Caller.DastyarStatus(HubResult<SrvStatus>.Success(status));
    }

    /// <summary>
    /// Sends PKCS#11 token information to caller if a device is connected.
    /// </summary>
    public async Task TokenInfo()
    {
        try
        {
            pkcs11Lib.LoadConnectedDevice();

            var info = pkcs11Lib.Token?.Info;
            var result = HubResult<TokenInfo?>.Success(info);
            await Clients.Caller.TokenInfo(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<TokenInfo?>.Failure(ex);
            await Clients.Caller.TokenInfo(result);
        }
    }

    /// <summary>
    /// Returns supported mechanism infos for the usable slot (or a placeholder if none).
    /// </summary>
    public async Task MechanismInfos()
    {
        try
        {
            pkcs11Lib.LoadConnectedDevice();

            var infos = pkcs11Lib.UsableSlot != null
                ? pkcs11Lib.UsableSlot.GetMechanismInfos()
                : [new MechanismInfo("No usable slots found.")];
            var result = HubResult<IEnumerable<MechanismInfo>?>.Success(infos);
            await Clients.Caller.MechanismInfos(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<IEnumerable<MechanismInfo>?>.Failure(ex);
            await Clients.Caller.MechanismInfos(result);
        }
    }

    /// <summary>
    /// Finds certificates only in current user store.
    /// </summary>
    /// <param name="findType">Optional X509FindType integer.</param>
    /// <param name="findValue">Search value (thumbprint, subject, etc.).</param>
    /// <param name="callback">Client callback correlation id.</param>
    public async Task StoreCertificates(int? findType, string? findValue, string callback)
    {
        try
        {
            var certificates = certificateProvider.FindCertificates(pkcs11Lib, StoreType.CurrentUser, findType, findValue, callback);
            var result = HubResult<IEnumerable<CertificateDetails>?>.Success(certificates, callback);
            await Clients.Caller.CertificateList(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<IEnumerable<CertificateDetails>?>.Failure(ex);
            await Clients.Caller.CertificateList(result);
        }
    }

    /// <summary>
    /// Finds certificates on hardware token only.
    /// </summary>
    public async Task TokenCertificates(int? findType, string? findValue, string callback)
    {
        try
        {
            var certificates = certificateProvider.FindCertificates(pkcs11Lib, StoreType.HardToken, findType, findValue, callback);
            var result = HubResult<IEnumerable<CertificateDetails>?>.Success(certificates, callback);
            await Clients.Caller.CertificateList(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<IEnumerable<CertificateDetails>?>.Failure(ex);
            await Clients.Caller.CertificateList(result);
        }
    }

    /// <summary>
    /// Finds certificates combining token and user store.
    /// </summary>
    public async Task TokenCertificatesFromStore(int? findType, string? findValue, string callback)
    {
        try
        {
            var certificates = certificateProvider.FindCertificates(pkcs11Lib, StoreType.Combine, findType, findValue, callback);
            var result = HubResult<IEnumerable<CertificateDetails>?>.Success(certificates, callback);
            await Clients.Caller.CertificateList(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<IEnumerable<CertificateDetails>?>.Failure(ex);
            await Clients.Caller.CertificateList(result);
        }
    }

    #region PKCS#1
    /// <summary>
    /// Encrypts data with RSA public key on token certificate.
    /// </summary>
    /// <param name="thumbprint">Certificate thumbprint.</param>
    /// <param name="data">Plaintext data (<= 245 bytes).</param>
    /// <param name="algorithm">Optional hash algorithm for OAEP.</param>
    /// <param name="mode">Padding mode.</param>
    public async Task EncryptByToken(string thumbprint,
                                     byte[] data,
                                     HashAlgorithmFlags? algorithm = null,
                                     RSAEncryptionPaddingMode? mode = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            if (data.Length > 245)
                throw new CryptographicException("Certificate encryption supports data with a maximum length of 245 bytes.");

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);

            if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
            {
                mode ??= RSAEncryptionPaddingMode.Pkcs1;
                algorithm ??= HashAlgorithmFlags.SHA256;
                var padding = mode.Value.ToRSAEncryptionPadding(algorithm.Value);
                var cipher = certificate.GetRSAPublicKey()?.Encrypt(data, padding);
                var result = HubResult<byte[]?>.Success(cipher);
                await Clients.Caller.Encrypt(result);
            }
            else
            {
                var result = HubResult<byte[]?>.Failure(100, "The key type does not support encryption/decryption.");
                await Clients.Caller.Encrypt(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Encrypt(result);
        }
    }

    /// <summary>
    /// Encrypts data with RSA public key in user store certificate.
    /// </summary>
    public async Task EncryptByStore(string thumbprint,
                                     byte[] data,
                                     HashAlgorithmFlags? algorithm = null,
                                     RSAEncryptionPaddingMode? mode = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            if (data.Length > 245)
                throw new CryptographicException("Certificate encryption supports data with a maximum length of 245 bytes.");

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;

            var rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                mode ??= RSAEncryptionPaddingMode.Pkcs1;
                algorithm ??= HashAlgorithmFlags.SHA256;
                var padding = mode.Value.ToRSAEncryptionPadding(algorithm.Value);
                var cipher = rsa.Encrypt(data, padding);
                var result = HubResult<byte[]?>.Success(cipher);
                await Clients.Caller.Encrypt(result);
            }
            else
            {
                var result = HubResult<byte[]?>.Failure(100, "The key type does not support encryption/decryption.");
                await Clients.Caller.Encrypt(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Encrypt(result);
        }
    }

    /// <summary>
    /// Decrypts cipher using RSA private key on token.
    /// </summary>
    public async Task DecryptByToken(string thumbprint,
                                     byte[] cipher,
                                     HashAlgorithmFlags? algorithm = null,
                                     RSAEncryptionPaddingMode? mode = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (cipher.Length == 0)
                throw new ArgumentException("The cipher is required.", nameof(cipher));

            await pkcs11Lib.CreateAuthenticatedSessionAsync();

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);

            if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
            {
                mode ??= RSAEncryptionPaddingMode.Pkcs1;
                algorithm ??= HashAlgorithmFlags.SHA256;
                var padding = mode.Value.ToRSAEncryptionPadding(algorithm.Value);
                var rsa = certificate.GetRSAPrivateKey();
                var data = rsa?.Decrypt(cipher, padding);
                var result = HubResult<byte[]?>.Success(data);
                await Clients.Caller.Decrypt(result);
            }
            else
            {
                var result = HubResult<byte[]?>.Failure(100, "The key type does not support encryption/decryption.");
                await Clients.Caller.Decrypt(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Decrypt(result);
        }
    }

    /// <summary>
    /// Decrypts cipher using RSA private key from user store.
    /// </summary>
    public async Task DecryptByStore(string thumbprint,
                                     byte[] cipher,
                                     HashAlgorithmFlags? algorithm = null,
                                     RSAEncryptionPaddingMode? mode = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (cipher.Length == 0)
                throw new ArgumentException("The cipher is required.", nameof(cipher));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;

            var rsa = certificate.GetRSAPrivateKey();
            if (rsa != null)
            {
                mode ??= RSAEncryptionPaddingMode.Pkcs1;
                algorithm ??= HashAlgorithmFlags.SHA256;
                var padding = mode.Value.ToRSAEncryptionPadding(algorithm.Value);
                var data = certificate.GetRSAPrivateKey()?.Decrypt(cipher, padding);
                var result = HubResult<byte[]?>.Success(data);
                await Clients.Caller.Decrypt(result);
            }
            else
            {
                var result = HubResult<byte[]?>.Failure(100, "The key type does not support encryption/decryption.");
                await Clients.Caller.Decrypt(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Decrypt(result);
        }
    }

    /// <summary>
    /// Signs raw data with token private key (RSA or ECDSA).
    /// </summary>
    public async Task SignDataByToken(string thumbprint,
                                      byte[] data,
                                      HashAlgorithmFlags? algorithm = null,
                                      RSASignaturePaddingMode? mode = null,
                                      DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            await pkcs11Lib.CreateAuthenticatedSessionAsync();

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);

            algorithm ??= HashAlgorithmFlags.SHA256;
            var hashAlg = algorithm.Value.ToHashAlgorithmName();

            if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
            {
                mode ??= RSASignaturePaddingMode.Pkcs1;
                var padding = mode.ToRSASignaturePadding();
                var rsa = certificate.GetRSAPrivateKey();
                var signature = rsa?.SignData(data, hashAlg, padding);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
            else
            {
                var ec = certificate.GetECDsaPrivateKey();
                var signature = format == null
                    ? ec?.SignData(data, hashAlg)
                    : ec?.SignData(data, hashAlg, format.Value);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Sign(result);
        }
    }

    /// <summary>
    /// Signs raw data with user store private key (RSA or ECDSA).
    /// </summary>
    public async Task SignDataByStore(string thumbprint,
                                      byte[] data,
                                      HashAlgorithmFlags? algorithm = null,
                                      RSASignaturePaddingMode? mode = null,
                                      DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;

            algorithm ??= HashAlgorithmFlags.SHA256;
            var hashAlg = algorithm.Value.ToHashAlgorithmName();
            var rsa = certificate.GetRSAPrivateKey();

            if (rsa != null)
            {
                var padding = mode.ToRSASignaturePadding();
                var signature = certificate.GetRSAPrivateKey()?.SignData(data, hashAlg, padding);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
            else
            {
                var signature = format == null
                    ? certificate.GetECDsaPrivateKey()?.SignData(data, hashAlg)
                    : certificate.GetECDsaPrivateKey()?.SignData(data, hashAlg, format.Value);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Sign(result);
        }
    }

    /// <summary>
    /// Signs a pre-computed hash with token private key.
    /// </summary>
    public async Task SignHashByToken(string thumbprint,
                                      byte[] hash,
                                      HashAlgorithmFlags? algorithm = null,
                                      RSASignaturePaddingMode? mode = null,
                                      DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (hash.Length == 0)
                throw new ArgumentException("The hash is required.", nameof(hash));

            await pkcs11Lib.CreateAuthenticatedSessionAsync();

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);

            if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
            {
                algorithm ??= HashAlgorithmFlags.SHA256;
                var hashAlg = algorithm.Value.ToHashAlgorithmName();
                var padding = mode.ToRSASignaturePadding();
                var rsa = certificate.GetRSAPrivateKey();
                var signature = rsa?.SignHash(hash, hashAlg, padding);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
            else
            {
                var ec = certificate.GetECDsaPrivateKey();
                var signature = format == null
                    ? ec?.SignHash(hash)
                    : ec?.SignHash(hash, format.Value);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Sign(result);
        }
    }

    /// <summary>
    /// Signs a pre-computed hash with user store private key.
    /// </summary>
    public async Task SignHashByStore(string thumbprint,
                                      byte[] hash,
                                      HashAlgorithmFlags? algorithm = null,
                                      RSASignaturePaddingMode? mode = null,
                                      DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (hash.Length == 0)
                throw new ArgumentException("The hash is required.", nameof(hash));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;

            var rsa = certificate.GetRSAPrivateKey();

            if (rsa != null)
            {
                algorithm ??= HashAlgorithmFlags.SHA256;
                var hashAlg = algorithm.Value.ToHashAlgorithmName();
                var padding = mode.ToRSASignaturePadding();
                var signature = certificate.GetRSAPrivateKey()?.SignHash(hash, hashAlg, padding);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
            else
            {
                var signature = format == null
                    ? certificate.GetECDsaPrivateKey()?.SignHash(hash)
                    : certificate.GetECDsaPrivateKey()?.SignHash(hash, format.Value);
                var result = HubResult<byte[]?>.Success(signature);
                await Clients.Caller.Sign(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Sign(result);
        }
    }

    /// <summary>
    /// Verifies signature over raw data using token certificate public key.
    /// </summary>
    public async Task VerifyDataByToken(string thumbprint,
                                        byte[] data,
                                        byte[] signature,
                                        HashAlgorithmFlags? algorithm = null,
                                        RSASignaturePaddingMode? mode = null,
                                        DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));
            if (signature.Length == 0)
                throw new ArgumentException("The signature is required.", nameof(signature));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);

            algorithm ??= HashAlgorithmFlags.SHA256;
            var hashAlg = algorithm.Value.ToHashAlgorithmName();

            if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
            {
                var padding = mode.ToRSASignaturePadding();
                var verified = certificate.GetRSAPublicKey()?.VerifyData(data, signature, hashAlg, padding);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
            else
            {
                var verified = format == null
                    ? certificate.GetECDsaPublicKey()?.VerifyData(data, signature, hashAlg)
                    : certificate.GetECDsaPublicKey()?.VerifyData(data, signature, hashAlg, format.Value);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<bool?>.Failure(ex);
            await Clients.Caller.Verify(result);
        }
    }

    /// <summary>
    /// Verifies signature over raw data using user store certificate public key.
    /// </summary>
    public async Task VerifyDataByStore(string thumbprint,
                                        byte[] data,
                                        byte[] signature,
                                        HashAlgorithmFlags? algorithm = null,
                                        RSASignaturePaddingMode? mode = null,
                                        DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));
            if (signature.Length == 0)
                throw new ArgumentException("The signature is required.", nameof(signature));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;

            algorithm ??= HashAlgorithmFlags.SHA256;
            var hashAlg = algorithm.Value.ToHashAlgorithmName();
            var rsa = certificate.GetRSAPrivateKey();

            if (rsa != null)
            {
                var padding = mode.ToRSASignaturePadding();
                var verified = certificate.GetRSAPublicKey()?.VerifyData(data, signature, hashAlg, padding);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
            else
            {
                var verified = format == null
                    ? certificate.GetECDsaPublicKey()?.VerifyData(data, signature, hashAlg)
                    : certificate.GetECDsaPublicKey()?.VerifyData(data, signature, hashAlg, format.Value);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<bool?>.Failure(ex);
            await Clients.Caller.Verify(result);
        }
    }

    /// <summary>
    /// Verifies signature over pre-computed hash using token certificate public key.
    /// </summary>
    public async Task VerifyHashByToken(string thumbprint,
                                        byte[] hash,
                                        byte[] signature,
                                        HashAlgorithmFlags? algorithm = null,
                                        RSASignaturePaddingMode? mode = null,
                                        DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (hash.Length == 0)
                throw new ArgumentException("The hash is required.", nameof(hash));
            if (signature.Length == 0)
                throw new ArgumentException("The signature is required.", nameof(signature));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);

            if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
            {
                algorithm ??= HashAlgorithmFlags.SHA256;
                var hashAlg = algorithm.Value.ToHashAlgorithmName();
                var padding = mode.ToRSASignaturePadding();
                var verified = certificate.GetRSAPublicKey()?.VerifyHash(hash, signature, hashAlg, padding);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
            else
            {
                var verified = format == null
                    ? certificate.GetECDsaPublicKey()?.VerifyHash(hash, signature)
                    : certificate.GetECDsaPublicKey()?.VerifyHash(hash, signature, format.Value);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<bool?>.Failure(ex);
            await Clients.Caller.Verify(result);
        }
    }

    /// <summary>
    /// Verifies signature over pre-computed hash using user store certificate public key.
    /// </summary>
    public async Task VerifyHashByStore(string thumbprint,
                                        byte[] hash,
                                        byte[] signature,
                                        HashAlgorithmFlags? algorithm = null,
                                        RSASignaturePaddingMode? mode = null,
                                        DSASignatureFormat? format = null)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (hash.Length == 0)
                throw new ArgumentException("The hash is required.", nameof(hash));
            if (signature.Length == 0)
                throw new ArgumentException("The signature is required.", nameof(signature));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;

            var rsa = certificate.GetRSAPrivateKey();

            if (rsa != null)
            {
                algorithm ??= HashAlgorithmFlags.SHA256;
                var hashAlg = algorithm.Value.ToHashAlgorithmName();
                var padding = mode.ToRSASignaturePadding();
                var verified = certificate.GetRSAPublicKey()?.VerifyHash(hash, signature, hashAlg, padding);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
            else
            {
                var verified = format == null
                    ? certificate.GetECDsaPublicKey()?.VerifyHash(hash, signature)
                    : certificate.GetECDsaPublicKey()?.VerifyHash(hash, signature, format.Value);
                var result = HubResult<bool?>.Success(verified);
                await Clients.Caller.Verify(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<bool?>.Failure(ex);
            await Clients.Caller.Verify(result);
        }
    }
    #endregion

    #region PKCS#7
    /// <summary>
    /// CMS encrypt using token certificates (RSA/OAEP or PKCS#1) with optional symmetric algorithm override.
    /// </summary>
    public async Task CmsEncryptByToken(string[] thumbprints,
                                        byte[] data,
                                        HashAlgorithmFlags? hashAlgorithm = null,
                                        RSAEncryptionPaddingMode? mode = null,
                                        EncryptionAlgorithm? encAlgorithm = null)
    {
        try
        {
            if (thumbprints.Length == 0)
                throw new ArgumentException("The certificate thumbprints are required.", nameof(thumbprints));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            var cmsRecipients = new CmsRecipientCollection();

            foreach (var thumbprint in thumbprints)
            {
                var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);

                if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
                {
                    if (mode == null)
                    {
                        cmsRecipients.Add(new CmsRecipient(certificate.Info.ParsedCertificate));
                    }
                    else
                    {
                        hashAlgorithm ??= HashAlgorithmFlags.SHA256;
                        mode ??= RSAEncryptionPaddingMode.Pkcs1;
                        var padding = mode.Value.ToRSAEncryptionPadding(hashAlgorithm.Value);
                        cmsRecipients.Add(new CmsRecipient(certificate.Info.ParsedCertificate, padding));
                    }
                }
            }

            if (cmsRecipients.Count < thumbprints.Length)
            {
                var failureResult = HubResult<byte[]?>.Failure(101, "At least one of the key types does not support encryption/decryption.");
                await Clients.Caller.CmsEncrypt(failureResult);
                return;
            }

            var contentInfo = new ContentInfo(data);
            var envelopedCms = encAlgorithm == null
                ? new EnvelopedCms(contentInfo)
                : new EnvelopedCms(contentInfo, encAlgorithm.Value.ToAlgorithmIdentifier());
            envelopedCms.Encrypt(cmsRecipients);
            var cipher = envelopedCms.Encode();
            var result = HubResult<byte[]?>.Success(cipher);
            await Clients.Caller.CmsEncrypt(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.CmsEncrypt(result);
        }
    }

    /// <summary>
    /// CMS encrypt using user store certificates.
    /// </summary>
    public async Task CmsEncryptByStore(string[] thumbprints,
                                        byte[] data,
                                        HashAlgorithmFlags? hashAlgorithm = null,
                                        RSAEncryptionPaddingMode? mode = null,
                                        EncryptionAlgorithm? encAlgorithm = null)
    {
        try
        {
            if (thumbprints.Length == 0)
                throw new ArgumentException("The certificate thumbprints are required.", nameof(thumbprints));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            using var store = new X509CertificateStore(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var cmsRecipients = new CmsRecipientCollection();

            foreach (var thumbprint in thumbprints)
            {
                var certificate = store.Certificates.FindCertificates(0, thumbprint).FirstOrDefault()
                    ?? throw new NullReferenceException("The certificate not found.");

                if (certificate.GetRSAPublicKey() != null)
                {
                    if (mode == null)
                    {
                        cmsRecipients.Add(new CmsRecipient(certificate));
                    }
                    else
                    {
                        hashAlgorithm ??= HashAlgorithmFlags.SHA256;
                        mode ??= RSAEncryptionPaddingMode.Pkcs1;
                        var padding = mode.Value.ToRSAEncryptionPadding(hashAlgorithm.Value);
                        cmsRecipients.Add(new CmsRecipient(certificate, padding));
                    }
                }
            }

            if (cmsRecipients.Count < thumbprints.Length)
            {
                var failureResult = HubResult<byte[]?>.Failure(101, "At least one of the key types does not support encryption/decryption.");
                await Clients.Caller.CmsEncrypt(failureResult);
                return;
            }

            var contentInfo = new ContentInfo(data);
            var envelopedCms = encAlgorithm == null
                ? new EnvelopedCms(contentInfo)
                : new EnvelopedCms(contentInfo, encAlgorithm.Value.ToAlgorithmIdentifier());
            envelopedCms.Encrypt(cmsRecipients);
            var cipher = envelopedCms.Encode();
            var result = HubResult<byte[]?>.Success(cipher);
            await Clients.Caller.CmsEncrypt(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.CmsEncrypt(result);
        }
    }

    /// <summary>
    /// CMS decrypt using token private key.
    /// </summary>
    public async Task CmsDecryptByToken(string thumbprint, byte[] cipher)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (cipher.Length == 0)
                throw new ArgumentException("The cipher is required.", nameof(cipher));

            await pkcs11Lib.CreateAuthenticatedSessionAsync();

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);
            var privateKey = certificate.GetPrivateKey()
                ?? throw new CryptographicException("Private key not found!");

            if (certificate.Info.KeyType == AsymmetricKeyType.RSA)
            {
                var envelopedCms = new EnvelopedCms();
                envelopedCms.Decode(cipher);
                var extraStore = new X509Certificate2Collection(certificate.Info.ParsedCertificate);
                foreach (var recipientInfo in envelopedCms.RecipientInfos)
                {
                    if (recipientInfo.RecipientIdentifier.MatchesCertificate(certificate.Info.ParsedCertificate))
                    {
                        envelopedCms.Decrypt(recipientInfo, privateKey);
                        break;
                    }
                }
                var data = envelopedCms.ContentInfo.Content;
                var result = HubResult<byte[]?>.Success(data);
                await Clients.Caller.CmsDecrypt(result);
            }
            else
            {
                var result = HubResult<byte[]?>.Failure(100, "The key type does not support encryption/decryption.");
                await Clients.Caller.CmsDecrypt(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.CmsDecrypt(result);
        }
    }

    /// <summary>
    /// CMS decrypt using user store private key.
    /// </summary>
    public async Task CmsDecryptByStore(string thumbprint, byte[] cipher)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (cipher.Length == 0)
                throw new ArgumentException("The cipher is required.", nameof(cipher));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;
            if (!certificate.HasPrivateKey)
                throw new CryptographicException("Private key not found!");

            if (certificate.GetRSAPrivateKey() != null)
            {
                var envelopedCms = new EnvelopedCms();
                var extraStore = new X509Certificate2Collection(certificate);
                envelopedCms.Decode(cipher);
                envelopedCms.Decrypt(extraStore);
                var data = envelopedCms.ContentInfo.Content;
                var result = HubResult<byte[]?>.Success(data);
                await Clients.Caller.CmsDecrypt(result);
            }
            else
            {
                var result = HubResult<byte[]?>.Failure(100, "The key type does not support encryption/decryption.");
                await Clients.Caller.CmsDecrypt(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.CmsDecrypt(result);
        }
    }

    /// <summary>
    /// CMS sign using token private key (optionally detached signature).
    /// </summary>
    public async Task CmsSignByToken(string thumbprint,
                                     byte[] data,
                                     bool detached = false)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            await pkcs11Lib.CreateAuthenticatedSessionAsync();

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);
            var privateKey = certificate.GetPrivateKey()
                ?? throw new CryptographicException("Private key not found!");

            var x509Certificate = certificate.Info.ParsedCertificate;
            var contentInfo = new ContentInfo(data);
            var signedCms = new SignedCms(contentInfo, detached);
            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, x509Certificate, privateKey);

            var x509chain = new X509Chain();
            x509chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            x509chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (x509chain.Build(x509Certificate))
            {
                var chain = x509chain.ChainElements
                    .Select(e => e.Certificate)
                    .ToArray();
                signer.Certificates.AddRange(chain);
            }
            signedCms.ComputeSignature(signer);
            var signature = signedCms.Encode();

            var result = HubResult<byte[]?>.Success(signature);
            await Clients.Caller.CmsSign(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.CmsSign(result);
        }
    }

    /// <summary>
    /// CMS sign using user store private key.
    /// </summary>
    public async Task CmsSignByStore(string thumbprint,
                                     byte[] data,
                                     bool detached = false)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (data.Length == 0)
                throw new ArgumentException("The data is required.", nameof(data));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;
            if (!certificate.HasPrivateKey)
                throw new CryptographicException("Private key not found!");

            var contentInfo = new ContentInfo(data);
            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate);

            var x509chain = new X509Chain();
            x509chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            x509chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (x509chain.Build(certificate))
            {
                var chain = x509chain.ChainElements
                    .Select(e => e.Certificate)
                    .ToArray();
                signer.Certificates.AddRange(chain);
            }
            var signedCms = new SignedCms(SubjectIdentifierType.IssuerAndSerialNumber, contentInfo, detached);
            signedCms.ComputeSignature(signer);
            var signature = signedCms.Encode();
            var result = HubResult<byte[]?>.Success(signature);
            await Clients.Caller.CmsSign(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.CmsSign(result);
        }
    }

    /// <summary>
    /// CMS verify signature using token certificate and optional original data.
    /// </summary>
    public async Task CmsVerifyByToken(string thumbprint,
                                       byte[] signedData,
                                       byte[]? originalData = null,
                                       bool validateCertificate = true)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (signedData.Length == 0)
                throw new ArgumentException("The signed data is required.", nameof(signedData));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.HardToken, thumbprint);
            var x509Certificate = certificate.Info.ParsedCertificate;

            SignedCms signedCms;
            if (originalData == null || originalData.Length == 0)
            {
                signedCms = new SignedCms();
            }
            else
            {
                var contentInfo = new ContentInfo(originalData);
                signedCms = new SignedCms(contentInfo, true);
            }
            signedCms.Decode(signedData);

            if (validateCertificate)
            {
                var x509chain = new X509Chain();
                x509chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                x509chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                if (x509chain.Build(x509Certificate))
                {
                    var chain = x509chain.ChainElements
                        .Select(e => e.Certificate)
                        .ToArray();
                    var extraStore = new X509Certificate2Collection(chain);
                    signedCms.CheckSignature(extraStore, !validateCertificate);
                }
                else
                {
                    signedCms.CheckSignature(!validateCertificate);
                }
            }
            else
            {
                signedCms.CheckSignature(!validateCertificate);
            }

            var certificates = new List<byte[]>();
            foreach (var signer in signedCms.SignerInfos)
            {
                if (signer.Certificate != null)
                {
                    certificates.Add(signer.Certificate.RawData);
                }
            }

            var result = originalData == null || originalData.Length == 0
                ? HubResult<CmsVerifyResult?>.Success(new CmsVerifyResult
                {
                    Certificates = [.. certificates],
                    OriginalData = signedCms.ContentInfo.Content,
                    Verified = true
                })
                : HubResult<CmsVerifyResult?>.Success(new CmsVerifyResult
                {
                    Certificates = [.. certificates],
                    Verified = true
                });
            await Clients.Caller.CmsVerify(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<CmsVerifyResult?>.Failure(ex);
            await Clients.Caller.CmsVerify(result);
        }
    }

    /// <summary>
    /// CMS verify signature using user store certificate.
    /// </summary>
    public async Task CmsVerifyByStore(string thumbprint,
                                       byte[] signedData,
                                       byte[]? originalData = null,
                                       bool validateCertificate = true)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint, nameof(thumbprint));
            if (signedData.Length == 0)
                throw new ArgumentException("The signed data is required.", nameof(signedData));

            var certificate = certificateProvider.FindCertificate(pkcs11Lib, StoreType.CurrentUser, thumbprint).Info.ParsedCertificate;

            SignedCms signedCms;
            if (originalData == null)
            {
                signedCms = new SignedCms();
            }
            else
            {
                var contentInfo = new ContentInfo(originalData);
                signedCms = new SignedCms(contentInfo, true);
            }
            signedCms.Decode(signedData);

            if (validateCertificate)
            {
                var x509chain = new X509Chain();
                x509chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                x509chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                if (x509chain.Build(certificate))
                {
                    var chain = x509chain.ChainElements
                        .Select(e => e.Certificate)
                        .ToArray();
                    var extraStore = new X509Certificate2Collection(chain);
                    signedCms.CheckSignature(extraStore, !validateCertificate);
                }
                else
                {
                    signedCms.CheckSignature(!validateCertificate);
                }
            }
            else
            {
                signedCms.CheckSignature(!validateCertificate);
            }

            var certificates = new List<byte[]>();
            foreach (var signer in signedCms.SignerInfos)
            {
                if (signer.Certificate != null)
                {
                    certificates.Add(signer.Certificate.RawData);
                }
            }

            var result = originalData == null || originalData.Length == 0
                ? HubResult<CmsVerifyResult?>.Success(new CmsVerifyResult
                {
                    Certificates = [.. certificates],
                    OriginalData = signedCms.ContentInfo.Content,
                    Verified = true
                })
                : HubResult<CmsVerifyResult?>.Success(new CmsVerifyResult
                {
                    Certificates = [.. certificates],
                    Verified = true
                });
            await Clients.Caller.CmsVerify(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<CmsVerifyResult?>.Failure(ex);
            await Clients.Caller.CmsVerify(result);
        }
    }
    #endregion

    #region PKCS#10
    /// <summary>
    /// Generates PKCS#10 CSR on token using requested key algorithm/size, returning DER or PEM.
    /// </summary>
    public async Task GenerateCSR(CertificateRequest request)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(request.CSP))
            {
                switch (request.CSP)
                {
                    case "EnterSafe ePass3003":
                        if (pkcs11Lib.ConnectedDeviceCSP?.Name != "USB Token EasyPlay USB Device")
                        {
                            var cspInfo = pkcs11Lib.SupportedProviders.SingleOrDefault(e => e.Name.Equals("USB Token EasyPlay USB Device"));
                            pkcs11Lib.Load(cspInfo);
                        }
                        break;
                    case "Longmai K3S Device":
                        if (pkcs11Lib.ConnectedDeviceCSP?.Name != "Longmai K3S USB Device")
                        {
                            var cspInfo = pkcs11Lib.SupportedProviders.SingleOrDefault(e => e.Name.Equals("Longmai K3S USB Device"));
                            pkcs11Lib.Load(cspInfo);
                        }
                        break;
                    case "SafeNet Key Storage":
                        if (pkcs11Lib.ConnectedDeviceCSP?.Name != "Rainbow iKey Token")
                        {
                            var cspInfo = pkcs11Lib.SupportedProviders.SingleOrDefault(e => e.Name.Equals("Rainbow iKey Token"));
                            pkcs11Lib.Load(cspInfo);
                        }
                        break;
                    default:
                        break;
                }
            }
            using var session = await pkcs11Lib.CreateAuthenticatedSessionAsync();

            if (request.KeyInfo.SignatureAlgorithm == SignatureAlgorithms.None)
                request.KeyInfo.SignatureAlgorithm = SignatureAlgorithms.SHA256WithRSA;
            request.SortSubjectDn(out string? commonName);

            byte[] ckaId;
            byte[] subjectPublicKeyInfo;
            KeyInfo publicKeyInfo;
            KeyInfo privateKeyInfo;

            switch (request.KeyInfo.SignatureAlgorithm)
            {
                case SignatureAlgorithms.SHA1WithRSA:
                case SignatureAlgorithms.SHA256WithRSA:
                case SignatureAlgorithms.SHA384WithRSA:
                case SignatureAlgorithms.SHA512WithRSA:
                    request.KeyInfo.KeySize ??= 2048;
                    pkcs11Lib.GenerateRsaKeyPair(session,
                                                 (ulong)request.KeyInfo.KeySize.Value,
                                                 commonName,
                                                 out publicKeyInfo,
                                                 out privateKeyInfo,
                                                 out subjectPublicKeyInfo,
                                                 out ckaId);
                    break;
                case SignatureAlgorithms.SHA1WithECDSA:
                case SignatureAlgorithms.SHA224WithECDSA:
                case SignatureAlgorithms.SHA256WithECDSA:
                case SignatureAlgorithms.SHA384WithECDSA:
                case SignatureAlgorithms.SHA512WithECDSA:
                    request.KeyInfo.EllipticCurve ??= EllipticCurveFlags.brainpoolP256r1;
                    pkcs11Lib.GenerateEcKeyPair(session,
                                                request.KeyInfo.EllipticCurve.Value,
                                                commonName,
                                                out publicKeyInfo,
                                                out privateKeyInfo,
                                                out subjectPublicKeyInfo,
                                                out ckaId);
                    break;
                default:
                    throw new NotSupportedException();
            }

            var mechanism = request.KeyInfo.SignatureAlgorithm.ToMechanism();
            var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
            var extensionCollection = CreateGeneralExtensions(request, publicKey, false);
            var extensions = extensionCollection.ToX509Extensions();
            var subjectDn = new X500DistinguishedName(ImproveSubjecDn(request.SubjectDn));

            PKCS11Library.GenerateCsrDER(session, privateKeyInfo, publicKeyInfo, subjectDn, mechanism, extensions, out byte[] pkcs10CSR);
            if (!session.CloseWhenDisposed)
                session.CloseSession();

            if (!request.PEM)
            {
                var result = HubResult<CsrResult<byte[]>?>.Success(new CsrResult<byte[]>
                {
                    CkaId = Convert.ToHexString(ckaId),
                    Label = publicKeyInfo.CkaLabel,
                    PKCS10CSR = pkcs10CSR
                });
                await Clients.Caller.CSR(result);
            }
            else
            {
                var csr = Convert.ToBase64String(pkcs10CSR, Base64FormattingOptions.InsertLineBreaks);
                var result = HubResult<CsrResult<string>?>.Success(new CsrResult<string>
                {
                    CkaId = Convert.ToHexString(ckaId),
                    Label = publicKeyInfo.CkaLabel,
                    PKCS10CSR = $"-----BEGIN CERTIFICATE REQUEST-----\n{csr}\n-----END CERTIFICATE REQUEST-----"
                });
                await Clients.Caller.CSR(result);
            }
        }
        catch (Exception ex)
        {
            var result = HubResult<CsrResult<string>?>.Failure(ex);
            await Clients.Caller.CSR(result);
        }
    }

    /// <summary>
    /// Imports a certificate to token, associating it with existing key pair (by CKA_ID).
    /// </summary>
    public async Task ImportToToken(string ckaId, string label, byte[] certificate)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(ckaId, nameof(ckaId));
            ArgumentException.ThrowIfNullOrWhiteSpace(label, nameof(label));
            if (certificate.Length == 0)
                throw new ArgumentException("The certificate is required.", nameof(certificate));

            using var session = await pkcs11Lib.CreateAuthenticatedSessionAsync();

            var keyId = Convert.FromHexString(ckaId);
#if NET9_0_OR_GREATER
            var x509Certificate = X509CertificateLoader.LoadCertificate(certificate);
#else
            var x509Certificate = new X509Certificate2(certificate);
#endif
            var certHandle = PKCS11Library.ImportCertificate(session, x509Certificate, keyId, label);
            if (!session.CloseWhenDisposed)
                session.CloseSession();

            var result = HubResult<bool?>.Success(certHandle.ObjectId > 0);
            await Clients.Caller.Import(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<bool?>.Failure(ex);
            await Clients.Caller.Import(result);
        }
    }

    /// <summary>
    /// Imports a certificate into current user store.
    /// </summary>
    public async Task ImportToStore(byte[] certificate)
    {
        try
        {
            if (certificate.Length == 0)
                throw new ArgumentException("The certificate is required.", nameof(certificate));

#if NET9_0_OR_GREATER
            var x509Certificate = X509CertificateLoader.LoadCertificate(certificate);
#else
            var x509Certificate = new X509Certificate2(certificate);
#endif
            using var store = new X509CertificateStore(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(x509Certificate);
            store.Close();

            var result = HubResult<bool?>.Success(true);
            await Clients.Caller.Import(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<bool?>.Failure(ex);
            await Clients.Caller.Import(result);
        }
    }

    /// <summary>
    /// Exports a certificate (DER) from token by thumbprint.
    /// </summary>
    public async Task ExportFromTokem(string thumbprint)
    {
        try
        {
            pkcs11Lib.LoadConnectedDevice();

            var certs = pkcs11Lib.Token?.Certificates;
            if (certs == null || certs.Count == 0)
                return;

            var certificate = certs
                .FirstOrDefault(e => e.Info.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))?
                .Info.ParsedCertificate
                .Export(X509ContentType.Cert);
            var result = HubResult<byte[]?>.Success(certificate);
            await Clients.Caller.Export(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Export(result);
        }
    }

    /// <summary>
    /// Exports a certificate (DER) from user store by thumbprint.
    /// </summary>
    public async Task ExportFromStore(string thumbprint)
    {
        try
        {
            using var store = new X509CertificateStore(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var certificate = store.Certificates
                .FindCertificates(0, thumbprint)
                .FirstOrDefault()?
                .Export(X509ContentType.Cert);

            var result = HubResult<byte[]?>.Success(certificate);
            await Clients.Caller.Export(result);
        }
        catch (Exception ex)
        {
            var result = HubResult<byte[]?>.Failure(ex);
            await Clients.Caller.Export(result);
        }
    }
    #endregion

    /// <summary>
    /// Sends a key PIN prompt to specified connection id.
    /// </summary>
    public async Task<PinResult> SendKeyPin(string connectionId)
        => await Clients.Client(connectionId).GetKeyPin();

    /// <summary>
    /// Sends a token PIN prompt to specified connection id.
    /// </summary>
    public async Task<PinResult> SendTokenPin(string connectionId)
        => await Clients.Client(connectionId).GetTokenPin();

    /// <summary>
    /// Selects a single certificate from a collection, prompting user if multiple present (Windows only).
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static X509Certificate2? SelectSingleCertificate(X509Certificate2Collection certificates)
    {
        switch (certificates.Count)
        {
            //case 0:
            //    return null;
            case 1:
                return certificates.First();
            default:
                var selectedCertificates = X509Certificate2UI.SelectFromCollection(certificates,
                                                                                   "Please select a certificate",
                                                                                   "Certificates in Hard Token/Windows Store",
                                                                                   X509SelectionFlag.SingleSelection);
                return selectedCertificates?.FirstOrDefault();
        }
    }

    //private static async Task<X509Certificate2?> SelectSingleCertificateAsync(X509Certificate2Collection certificates)
    //{
    //    switch (certificates.Count)
    //    {
    //        case 1:
    //            return certificates.First();
    //        default:
    //        {
    //            // Build a view-model containing the certificates so the window can display them.
    //            var vm = new X509CertificateUI.ViewModels.CertificateSelectionViewModel();
    //            foreach (var cert in certificates)
    //                vm.Certificates.Add(cert);

    //            var window = new X509Store.X509CertificateUI.Desktop.Views.CertificateSelectionWindow(vm);

    //            // Ensure we show the dialog on the Avalonia UI thread and await the result.
    //            X509Certificate2? selected = null;
    //            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(async () =>
    //            {
    //                // parent window is null when there is no owner; adjust if you have a main window instance.
    //                selected = await window.ShowDialog<X509Certificate2?>(null);
    //            });

    //            return selected;
    //        }
    //    }
    //}

    private static X509ExtensionCollection CreateGeneralExtensions(CertificateRequest request, PublicKey publicKey, bool isCA = false)
    {
        var keyInfo = request.KeyInfo;

        var extensions = new X509ExtensionCollection
        {
            new X509BasicConstraintsExtension(isCA, false, 0, keyInfo.BasicConstraintsCritical),
            new X509SubjectKeyIdentifierExtension(publicKey, keyInfo.SubjectKeyIdentifierCritical),
        };
        if (request.SubjectAltNames != null)
        {
            var subjectAltNamesExtension = request.SubjectAltNames.ToX509Extension();
            if (subjectAltNamesExtension != null)
                extensions.Add(subjectAltNamesExtension);
        }

        return extensions;
    }

    /// <summary>
    /// Improves and normalizes the subjectDn for X.500 distinguished names.
    /// </summary>
    /// <param name="subjectDn">The subject distinguished names.</param>
    /// <returns>The normalized subjectDn string.</returns>
    private static string ImproveSubjecDn(string subjectDn)
    {
        return subjectDn.Replace("ORGANIZATIONIDENTIFIER", Oids.OrganizationIdentifier)
            .Replace("POSTALADDRESS", Oids.PostalAddress);
    }
}
