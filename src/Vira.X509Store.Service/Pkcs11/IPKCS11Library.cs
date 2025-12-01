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
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1.X509;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Vira.Caching.Services;
using Vira.X509Store.Service.Hubs;

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Abstraction over PKCS#11 token interactions and helper operations used by the service.
/// Provides loading/unloading of providers, session creation/authentication, key generation,
/// CSR generation and convenience accessors to the connected token and store contexts.
/// </summary>
public interface IPKCS11Library
{
    /// <summary>
    /// Default timeout (in milliseconds) for asynchronous operations that require user input
    /// or device interaction (e.g., PIN entry, login, session creation).
    /// </summary>
    internal const int MillisecondsTimeout = 30_000;

    /// <summary>
    /// Gets a value indicating whether a PKCS#11 provider/library is currently loaded.
    /// </summary>
    bool IsLoaded { get; }

    /// <summary>
    /// Gets information about the currently connected/loaded device provider (CSP/KSP mapping).
    /// </summary>
    CspInfo? ConnectedDeviceCSP { get; }

    /// <summary>
    /// Gets the usable slot selected for operations (if any).
    /// </summary>
    Slot? UsableSlot { get; }

    /// <summary>
    /// Gets the connected token wrapper providing access to objects and metadata.
    /// </summary>
    Token? Token { get; }

    /// <summary>
    /// Gets the PKCS#11-backed X.509 store wrapper.
    /// </summary>
    X509Store? Store { get; }

    /// <summary>
    /// Gets or sets the list of supported provider configurations that can be loaded.
    /// </summary>
    IEnumerable<CspInfo> SupportedProviders { get; set; }

    /// <summary>
    /// Gets or sets the cached key PIN (user PIN for private key use) when available.
    /// </summary>
    SecureString? KeyPin { get; set; }

    /// <summary>
    /// Gets or sets the cached token PIN (login PIN) when available.
    /// </summary>
    SecureString? TokenPin { get; set; }

    /// <summary>
    /// Gets an optional cache service used for cross-call state (e.g., connection ids).
    /// </summary>
    ICacheService? Cache { get; }

    /// <summary>
    /// Gets an optional SignalR hub context used to prompt clients (e.g., for PIN entry).
    /// </summary>
    IHubContext<TokenHub>? Hub { get; }

    /// <summary>
    /// Loads a PKCS#11 provider and initializes the store and slot list.
    /// </summary>
    /// <param name="cspInfo">Provider configuration to load; null may attempt auto-detection.</param>
    /// <param name="slotsType">Slot enumeration filter (e.g., with token present only).</param>
    void Load(CspInfo? cspInfo, SlotsType slotsType = SlotsType.WithTokenPresent);

    /// <summary>
    /// Unloads the current provider and releases any associated resources.
    /// </summary>
    void Unload();

    /// <summary>
    /// Attempts to load and prepare the currently connected device based on known providers.
    /// </summary>
    void LoadConnectedDevice();

    /// <summary>
    /// Generates an ECDSA key pair on the token and creates a DER-encoded PKCS#10 CSR.
    /// </summary>
    /// <param name="session">Authenticated session to use.</param>
    /// <param name="subjectDn">Subject distinguished name.</param>
    /// <param name="label">Optional key label.</param>
    /// <param name="mechanismType">Signature mechanism for CSR (e.g., CKM_ECDSA_SHA256).</param>
    /// <param name="ellipticCurve">Named curve identifier.</param>
    /// <param name="extensions">Extensions to include in the CSR.</param>
    /// <param name="keyId">Outputs the generated key identifier (CKA_ID).</param>
    /// <param name="csrDER">Outputs the DER-encoded CSR bytes.</param>
    void GenerateEcCsrDER(ISession session,
                          X500DistinguishedName subjectDn,
                          string? label,
                          CKM mechanismType,
                          EllipticCurveFlags ellipticCurve,
                          X509Extensions extensions,
                          out byte[] keyId,
                          out byte[] csrDER);

    /// <summary>
    /// Generates an ECDSA key pair on the token and creates a PEM-encoded PKCS#10 CSR.
    /// </summary>
    /// <param name="session">Authenticated session to use.</param>
    /// <param name="subjectDn">Subject distinguished name.</param>
    /// <param name="label">Optional key label.</param>
    /// <param name="mechanismType">Signature mechanism for CSR.</param>
    /// <param name="ellipticCurve">Named curve identifier.</param>
    /// <param name="extensions">Extensions to include in the CSR.</param>
    /// <param name="keyId">Outputs the generated key identifier (CKA_ID).</param>
    /// <param name="csrPEM">Outputs the PEM-encoded CSR string.</param>
    void GenerateEcCsrPEM(ISession session,
                          X500DistinguishedName subjectDn,
                          string? label,
                          CKM mechanismType,
                          EllipticCurveFlags ellipticCurve,
                          X509Extensions extensions,
                          out byte[] keyId,
                          out string csrPEM);

    /// <summary>
    /// Generates an EC key pair on the token and returns key metadata and SubjectPublicKeyInfo.
    /// </summary>
    /// <param name="session">Authenticated session to use.</param>
    /// <param name="ellipticCurve">Named curve identifier.</param>
    /// <param name="label">Optional key label.</param>
    /// <param name="publicKeyInfo">Outputs public key object info.</param>
    /// <param name="privateKeyInfo">Outputs private key object info.</param>
    /// <param name="subjectPublicKeyInfo">Outputs the SPKI bytes.</param>
    /// <param name="ckaId">Outputs the key identifier (CKA_ID).</param>
    void GenerateEcKeyPair(ISession session,
                           EllipticCurveFlags ellipticCurve,
                           string? label,
                           out KeyInfo publicKeyInfo,
                           out KeyInfo privateKeyInfo,
                           out byte[] subjectPublicKeyInfo,
                           out byte[] ckaId);

    /// <summary>
    /// Generates an RSA key pair on the token and creates a DER-encoded PKCS#10 CSR.
    /// </summary>
    /// <param name="session">Authenticated session to use.</param>
    /// <param name="subjectDn">Subject distinguished name.</param>
    /// <param name="label">Optional key label.</param>
    /// <param name="mechanismType">Signature mechanism for CSR (e.g., CKM_SHA256_RSA_PKCS).</param>
    /// <param name="keySize">RSA key size.</param>
    /// <param name="extensions">Extensions to include in the CSR.</param>
    /// <param name="keyId">Outputs the generated key identifier (CKA_ID).</param>
    /// <param name="csrDER">Outputs the DER-encoded CSR bytes.</param>
    void GenerateRsaCsrDER(ISession session,
                           X500DistinguishedName subjectDn,
                           string? label,
                           CKM mechanismType,
                           ulong keySize,
                           X509Extensions extensions,
                           out byte[] keyId,
                           out byte[] csrDER);

    /// <summary>
    /// Generates an RSA key pair on the token and creates a PEM-encoded PKCS#10 CSR.
    /// </summary>
    /// <param name="session">Authenticated session to use.</param>
    /// <param name="subjectDn">Subject distinguished name.</param>
    /// <param name="label">Optional key label.</param>
    /// <param name="mechanismType">Signature mechanism for CSR.</param>
    /// <param name="keySize">RSA key size.</param>
    /// <param name="extensions">Extensions to include in the CSR.</param>
    /// <param name="keyId">Outputs the generated key identifier (CKA_ID).</param>
    /// <param name="csrPEM">Outputs the PEM-encoded CSR string.</param>
    void GenerateRsaCsrPEM(ISession session,
                           X500DistinguishedName subjectDn,
                           string? label,
                           CKM mechanismType,
                           ulong keySize,
                           X509Extensions extensions,
                           out byte[] keyId,
                           out string csrPEM);

    /// <summary>
    /// Generates an RSA key pair on the token and returns key metadata and SubjectPublicKeyInfo.
    /// </summary>
    /// <param name="session">Authenticated session to use.</param>
    /// <param name="keyLength">RSA key size.</param>
    /// <param name="label">Optional key label.</param>
    /// <param name="publicKeyInfo">Outputs public key object info.</param>
    /// <param name="privateKeyInfo">Outputs private key object info.</param>
    /// <param name="subjectPublicKeyInfo">Outputs the SPKI bytes.</param>
    /// <param name="ckaId">Outputs the key identifier (CKA_ID).</param>
    void GenerateRsaKeyPair(ISession session,
                            ulong keyLength,
                            string? label,
                            out KeyInfo publicKeyInfo,
                            out KeyInfo privateKeyInfo,
                            out byte[] subjectPublicKeyInfo,
                            out byte[] ckaId);

    /// <summary>
    /// Creates an authenticated session with the token, requesting PIN if needed.
    /// </summary>
    /// <param name="sessionType">Read-only or read-write session.</param>
    /// <param name="millisecondsTimeout">Timeout for login/PIN prompt operations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Authenticated PKCS#11 session.</returns>
    Task<ISession> CreateAuthenticatedSessionAsync(SessionType sessionType = SessionType.ReadWrite,
                                                   int millisecondsTimeout = MillisecondsTimeout,
                                                   CancellationToken cancellationToken = default);

    /// <summary>
    /// Ensures the current context is logged-in to the token, prompting for PIN if necessary.
    /// </summary>
    /// <param name="millisecondsTimeout">Timeout for login/PIN prompt operations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LoginSessionAsync(int millisecondsTimeout = MillisecondsTimeout, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requests the key (user) PIN from a client via hub callback and caches it when provided.
    /// </summary>
    /// <param name="millisecondsTimeout">Timeout for the request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>PIN entry result including status and/or provided PIN.</returns>
    Task<PinResult> RequestKeyPinAsync(int millisecondsTimeout = MillisecondsTimeout, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requests the token login PIN from a client via hub callback and caches it when provided.
    /// </summary>
    /// <param name="millisecondsTimeout">Timeout for the request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>PIN entry result including status and/or provided PIN.</returns>
    Task<PinResult> RequestTokenPinAsync(int millisecondsTimeout = MillisecondsTimeout, CancellationToken cancellationToken = default);
}
