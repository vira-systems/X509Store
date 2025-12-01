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
using Org.BouncyCastle.X509;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Vira.Caching.Services;
using Vira.X509Store.Service.Hubs;
using Vira.X509Store.Service.Pkcs11;

namespace Vira.X509Store.Service;

/// <summary>
/// Default implementation of <see cref="IPKCS11Library"/> that manages provider loading,
/// token discovery, session authentication, key generation and CSR creation. Also integrates
/// with SignalR to request PINs from a connected client when needed.
/// </summary>
public partial class PKCS11Library(ICacheService? cache,
                                    IHubContext<TokenHub>? hub,
                                    ILogger<PKCS11Library> logger) : IPKCS11Library, IDisposable, IAsyncDisposable
{
    // Semaphore used to serialize PIN prompts so multiple concurrent callers do not trigger multiple client prompts
    private readonly SemaphoreSlim _pinSemaphore = new(1, 1);

    private bool _disposed;

    /// <inheritdoc />
    public bool IsLoaded { get; private set; }

    /// <inheritdoc />
    public CspInfo? ConnectedDeviceCSP { get; private set; }

    /// <inheritdoc />
    public Slot? UsableSlot { get; private set; }

    /// <inheritdoc />
    public Token? Token { get; private set; }

    /// <summary>
    /// Gets the PKCS#11-backed X509 store wrapper created when a provider is loaded.
    /// </summary>
    public Pkcs11.X509Store? Store { get; private set; }

    /// <inheritdoc />
    public IEnumerable<CspInfo> SupportedProviders { get; set; } = [];

    /// <inheritdoc />
    public SecureString? KeyPin { get; set; }

    /// <inheritdoc />
    public SecureString? TokenPin { get; set; }

    /// <inheritdoc />
    public ICacheService? Cache { get; } = cache;

    /// <inheritdoc />
    public IHubContext<TokenHub>? Hub { get; } = hub;

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, nameof(PKCS11Library));
    }

    /// <inheritdoc />
    public void Load(CspInfo? cspInfo, SlotsType slotsType = SlotsType.WithTokenPresent)
    {
        ThrowIfDisposed();
        ConnectedDeviceCSP = cspInfo;
        if (cspInfo == null)
            return;

        var pkcs11Library = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.SystemDirectory, cspInfo.WinLib)
            : OperatingSystem.IsMacCatalyst() || OperatingSystem.IsMacOS()
                ? cspInfo.MacLib
                : OperatingSystem.IsLinux()
                    ? cspInfo.LnxLib
                    : throw new PlatformNotSupportedException();
        var pkcs11LibraryPath = Path.Combine(Environment.SystemDirectory, pkcs11Library);

        try
        {
            Unload();
            ConnectedDeviceCSP = cspInfo;
            Store = new Pkcs11.X509Store(pkcs11LibraryPath, slotsType, this);
            UsableSlot = Store.Slots?.FirstOrDefault(e => e?.Token != null);
            Token = UsableSlot?.Token;
        }
        catch (Exception ex)
        {
            // Pkcs11Interop uses native functions from "libdl.so", but Ubuntu 22.04 and possibly also other distros have "libdl.so.2".
            if (Environment.OSVersion.Platform == PlatformID.Unix && Environment.OSVersion.Version.Major >= 22 && Environment.OSVersion.Version.Minor >= 04)
            {
                SetupCustomDllImportResolver();
                pkcs11LibraryPath = Path.Combine(Environment.SystemDirectory, "libdl.so.2");
                Store = new Pkcs11.X509Store(pkcs11LibraryPath, slotsType, this);
                return;
            }
            logger.LogError(ex, "Load library failed. {PATH}", pkcs11LibraryPath);
            throw;
        }

        IsLoaded = true;
    }

    /// <inheritdoc />
    public void Unload()
    {
        // allow Unload to be called multiple times safely
        ConnectedDeviceCSP = null;
        KeyPin = null;
        TokenPin = null;

        if (Token?.IsDisposed == false)
        {
            Token.Dispose();
            Token = null;
        }
        if (UsableSlot?.IsDisposed == false)
        {
            UsableSlot.Dispose();
            UsableSlot = null;
        }
        if (Store?.IsDisposed == false)
        {
            Store.Dispose();
            Store = null;
        }

        IsLoaded = false;
    }

    /// <inheritdoc />
    public void LoadConnectedDevice()
    {
        ThrowIfDisposed();
        if (IsLoaded || ConnectedDeviceCSP != null || !OperatingSystem.IsWindows())
            return;

        var query = "SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%'";
        using var searcher = new ManagementObjectSearcher(query);

        CspInfo? cspInfo = null;
        foreach (var device in searcher.Get())
        {
            var name = device.Properties["Name"].Value;
            cspInfo = SupportedProviders.SingleOrDefault(e => e.Name.Equals(name));
            if (cspInfo != null)
                break;
        }

        if (cspInfo != null && Cache != null && Hub != null)
        {
            Load(cspInfo);
        }
    }

    #region PKCS#11 Functions

    /// <inheritdoc />
    public void GenerateEcCsrDER(ISession session,
                                 X500DistinguishedName subjectDn,
                                 string? label,
                                 CKM mechanismType,
                                 EllipticCurveFlags ellipticCurve,
                                 X509Extensions extensions,
                                 out byte[] keyId,
                                 out byte[] csrDER)
    {
        GenerateEcKeyPair(session, ellipticCurve, label, out KeyInfo publicKeyInfo, out KeyInfo privateKeyInfo, out _, out keyId);
        GenerateCsrDER(session, privateKeyInfo, publicKeyInfo, subjectDn, mechanismType, extensions, out csrDER);
    }

    /// <inheritdoc />
    public void GenerateEcCsrPEM(ISession session,
                                 X500DistinguishedName subjectDn,
                                 string? label,
                                 CKM mechanismType,
                                 EllipticCurveFlags ellipticCurve,
                                 X509Extensions extensions,
                                 out byte[] keyId,
                                 out string csrPEM)
    {
        GenerateEcKeyPair(session, ellipticCurve, label, out KeyInfo publicKeyInfo, out KeyInfo privateKeyInfo, out _, out keyId);
        GenerateCsrPEM(session, (CKK)publicKeyInfo.CkaKeyType, publicKeyInfo.ObjectHandle, privateKeyInfo.ObjectHandle, subjectDn, mechanismType, extensions, out csrPEM);
    }

    /// <inheritdoc />
    public void GenerateEcKeyPair(ISession session,
                                  EllipticCurveFlags ellipticCurve,
                                  string? label,
                                  out KeyInfo publicKeyInfo,
                                  out KeyInfo privateKeyInfo,
                                  out byte[] subjectPublicKeyInfo,
                                  out byte[] ckaId)
    {
        if (UsableSlot?.GetMechanismInfo(CKM.CKM_EC_KEY_PAIR_GEN).MechanismFlags.GenerateKeyPair != true)
            throw new CryptographicException(NotSupportedEcKeyType);

#if NET9_0_OR_GREATER
        var keyId = Guid.CreateVersion7(DateTimeOffset.UtcNow);
#else
        var keyId = Guid.NewGuid();
#endif
        label ??= keyId.ToString();
        ckaId = keyId.ToByteArray();

        var x962Parameters = Utils.GetX962Parameters(ellipticCurve);
        byte[] ecParams = x962Parameters.GetDerEncoded();

        using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_EC_KEY_PAIR_GEN);

        var publicKeyObjectAttributes = KeyUtils.CreateDefaultEcPublicKeyAttribute(session, CKK.CKK_EC, label, ckaId, ecParams);
        var privateKeyObjectAttributes = KeyUtils.CreateDefaultPrivateKeyAttribute(session, CKK.CKK_EC, label, ckaId);

        session.GenerateKeyPair(mechanism, publicKeyObjectAttributes, privateKeyObjectAttributes, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle);

        publicKeyInfo = new KeyInfo(publicKeyHandle, publicKeyObjectAttributes, Utils.GetObjectSize(session, publicKeyHandle));
        privateKeyInfo = new KeyInfo(privateKeyHandle, privateKeyObjectAttributes, Utils.GetObjectSize(session, privateKeyHandle));

        var publicKeyParameters = Utils.GetEcPublicKeyParams(session, publicKeyHandle, out _);
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKeyParameters);
        subjectPublicKeyInfo = spki.GetDerEncoded();
    }

    /// <inheritdoc />
    public void GenerateRsaCsrDER(ISession session,
                                  X500DistinguishedName subjectDn,
                                  string? label,
                                  CKM mechanismType,
                                  ulong keySize,
                                  X509Extensions extensions,
                                  out byte[] keyId,
                                  out byte[] csrDER)
    {
        GenerateRsaKeyPair(session, keySize, label, out KeyInfo publicKeyInfo, out KeyInfo privateKeyInfo, out _, out keyId);
        GenerateCsrDER(session, privateKeyInfo, publicKeyInfo, subjectDn, mechanismType, extensions, out csrDER);
    }

    /// <inheritdoc />
    public void GenerateRsaCsrPEM(ISession session,
                                  X500DistinguishedName subjectDn,
                                  string? label,
                                  CKM mechanismType,
                                  ulong keySize,
                                  X509Extensions extensions,
                                  out byte[] keyId,
                                  out string csrPEM)
    {
        GenerateRsaKeyPair(session, keySize, label, out KeyInfo publicKeyInfo, out KeyInfo privateKeyInfo, out _, out keyId);
        GenerateCsrPEM(session, (CKK)publicKeyInfo.CkaKeyType, publicKeyInfo.ObjectHandle, privateKeyInfo.ObjectHandle, subjectDn, mechanismType, extensions, out csrPEM);
    }

    /// <inheritdoc />
    public void GenerateRsaKeyPair(ISession session,
                                   ulong keyLength,
                                   string? label,
                                   out KeyInfo publicKeyInfo,
                                   out KeyInfo privateKeyInfo,
                                   out byte[] subjectPublicKeyInfo,
                                   out byte[] ckaId)
    {
        if (UsableSlot?.GetMechanismInfo(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN).MechanismFlags.GenerateKeyPair != true)
            throw new CryptographicException(NotSupportedRsaKeyType);


#if NET9_0_OR_GREATER
        var keyId = Guid.CreateVersion7(DateTimeOffset.UtcNow);
#else
        var keyId = Guid.NewGuid();
#endif
        label ??= keyId.ToString();
        ckaId = keyId.ToByteArray();

        using IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        var publicKeyObjectAttributes = KeyUtils.CreateDefaultRsaPublicKeyAttribute(session, CKK.CKK_RSA, label, ckaId, keyLength);
        var privateKeyObjectAttributes = KeyUtils.CreateDefaultPrivateKeyAttribute(session, CKK.CKK_RSA, label, ckaId);

        session.GenerateKeyPair(mechanism, publicKeyObjectAttributes, privateKeyObjectAttributes, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle);

        publicKeyInfo = new KeyInfo(publicKeyHandle, publicKeyObjectAttributes, Utils.GetObjectSize(session, publicKeyHandle));
        privateKeyInfo = new KeyInfo(privateKeyHandle, privateKeyObjectAttributes, Utils.GetObjectSize(session, privateKeyHandle));

        var publicKeyParameters = Utils.GetRsaPublicKeyParams(session, publicKeyHandle, out _);
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKeyParameters);
        subjectPublicKeyInfo = spki.GetDerEncoded();
    }
    #endregion

    /// <inheritdoc />
    public async Task<ISession> CreateAuthenticatedSessionAsync(SessionType sessionType = SessionType.ReadWrite,
                                                                int millisecondsTimeout = IPKCS11Library.MillisecondsTimeout,
                                                                CancellationToken cancellationToken = default)
    {
        LoadConnectedDevice();

        if (UsableSlot == null)
            throw new InvalidOperationException("There is no any usable slot.");

        var session = UsableSlot.OpenNewSession(sessionType);
        if (TokenPin == null)
        {
            var pinResult = await RequestTokenPinAsync(millisecondsTimeout, cancellationToken);
            if (pinResult.Cancel)
            {
                // Caller cancelled PIN entry - dispose session and propagate
                try { session.Dispose(); } catch { }
                throw new LoginCancelledException("Token PIN entry was cancelled by user.");
            }
        }

        var sessionInfo = session.IsAuthenticated();
        if (sessionInfo.CanAuthenticate && !sessionInfo.IsAuthenticated)
        {
            // Ensure TokenPin is present before attempting to login
            if (TokenPin == null)
            {
                try { session.Dispose(); } catch { }
                throw new LoginCancelledException("No token PIN available to perform login.");
            }

            try
            {
                session.Login(CKU.CKU_USER, TokenPin?.ToPlainString());
                UsableSlot.LoginSession(TokenPin?.ToPlainString());
            }
            catch (Pkcs11Exception pkex)
            {
                var friendly = pkex.GetFriendlyMessage();
                logger.LogError(pkex, "PKCS#11 login failed: {Reason}", friendly);
                try { session.Dispose(); } catch { }
                // Surface a clearer exception to callers
                throw new InvalidOperationException(friendly, pkex);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error during token login.");
                try { session.Dispose(); } catch { }
                throw;
            }
        }

        return session;
    }

    /// <inheritdoc />
    public async Task LoginSessionAsync(int millisecondsTimeout = IPKCS11Library.MillisecondsTimeout,
                                        CancellationToken cancellationToken = default)
    {
        LoadConnectedDevice();

        if (UsableSlot == null)
            throw new InvalidOperationException("There is no any usable slot.");

        var sessionInfo = Token!.Session?.IsAuthenticated();
        if (sessionInfo?.CanAuthenticate == true && sessionInfo?.IsAuthenticated != true)
        {
            if (TokenPin == null)
            {
                await RequestTokenPinAsync(millisecondsTimeout, cancellationToken);
            }
        }

        UsableSlot.LoginSession(TokenPin?.ToPlainString());
    }

    /// <inheritdoc />
    public async Task<PinResult> RequestKeyPinAsync(int millisecondsTimeout = IPKCS11Library.MillisecondsTimeout,
                                                    CancellationToken cancellationToken = default)
    {
        if (KeyPin != null)
            return new PinResult(false, KeyPin.ToPlainString());

        return await RequestPinAsync(PinType.KeyPin, millisecondsTimeout, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<PinResult> RequestTokenPinAsync(int millisecondsTimeout = IPKCS11Library.MillisecondsTimeout,
                                                      CancellationToken cancellationToken = default)
    {
        if (TokenPin != null)
            return new PinResult(false, TokenPin.ToPlainString());

        if (Token?.Info.HasProtectedAuthenticationPath == true)
        {
            Console.Write("Please use protected authentication path to enter token PIN...");
            return new PinResult(cancel: false, pin: null);
        }

        return await RequestPinAsync(PinType.TokenPin, millisecondsTimeout, cancellationToken);
    }

    /// <summary>
    /// Requests a PIN from client via SignalR, enforcing a single concurrent prompt and respecting a timeout.
    /// </summary>
    private async Task<PinResult> RequestPinAsync(PinType pinType,
                                                  int millisecondsTimeout = IPKCS11Library.MillisecondsTimeout,
                                                  CancellationToken cancellationToken = default)
    {
        // Measure elapsed time so we can apply the provided timeout across both semaphore wait and client invoke.
        var sw = Stopwatch.StartNew();

        // Attempt to acquire the semaphore within the overall timeout
        var acquired = await _pinSemaphore.WaitAsync(millisecondsTimeout, cancellationToken);

        // If we didn't acquire the semaphore within the timeout, surface a timeout
        if (!acquired)
        {
            logger.LogWarning("Timeout waiting for PIN prompt lock (pinType: {PinType}).", pinType);
            throw new TimeoutException("Timed out waiting for PIN prompt lock.");
        }

        try
        {
            // Compute remaining time for the client InvokeAsync
            sw.Stop();
            var elapsed = (int)sw.ElapsedMilliseconds;
            var remaining = millisecondsTimeout - elapsed;
            if (remaining <= 0)
            {
                logger.LogWarning("No remaining timeout for PIN request after semaphore acquisition (method: {Method}).", pinType);
                throw new TimeoutException("Timed out waiting for PIN prompt lock.");
            }

            // Re-check to avoid duplicate prompts if another caller already set the PIN
            switch (pinType)
            {
                case PinType.KeyPin:
                    if (KeyPin != null)
                        return new PinResult(false, KeyPin.ToPlainString());
                    break;
                case PinType.TokenPin:
                    if (TokenPin != null)
                        return new PinResult(false, TokenPin.ToPlainString());
                    break;
                default:
                    break;
            }

            try
            {
                var connectionId = Cache?.Get<string>("SINGLE_CLIENT_ID");
                if (!string.IsNullOrEmpty(connectionId))
                {
                    // Create a linked cancellation token source that cancels after the remaining timeout or when caller cancels
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    cts.CancelAfter(remaining);

                    try
                    {
                        // Invoke the client method with the timeout-aware token
                        var result = await Hub!.Clients.Client(connectionId).InvokeAsync<PinResult>($"Get{pinType}", cts.Token);

                        // If client didn't return a result, treat as cancellation
                        if (result == null)
                        {
                            logger.LogWarning("Client returned null for PIN request (method: {Method}, connectionId: {ConnectionId}). Treating as cancellation.", pinType, connectionId);
                            return new PinResult(true, null);
                        }

                        // Store the pin securely based on the type of request
                        switch (pinType)
                        {
                            case PinType.KeyPin:
                                KeyPin = result.Cancel == false ? result.Pin?.ToSecureString() : null;
                                break;
                            case PinType.TokenPin:
                                TokenPin = result.Cancel == false ? result.Pin?.ToSecureString() : null;
                                break;
                            default:
                                break;
                        }

                        return result;
                    }
                    catch (OperationCanceledException oce)
                    {
                        // Determine whether cancellation was due to timeout or external cancellation
                        if (cancellationToken.IsCancellationRequested)
                        {
                            logger.LogInformation(oce, "PIN request cancelled by external token (method: {Method}, connectionId: {ConnectionId}).", pinType, connectionId);
                        }
                        else
                        {
                            logger.LogWarning(oce, "PIN request timed out waiting for client response (method: {Method}, connectionId: {ConnectionId}).", pinType, connectionId);
                        }

                        // Return a result indicating the operation was cancelled so callers can handle it
                        return new PinResult(true, null);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Request PIN failed while invoking client. {METHOD} (connectionId: {ConnectionId})", pinType, connectionId);
                        throw;
                    }
                }

                // No client connected; return a non-cancel result with no PIN
                return new PinResult(false, null);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Request PIN failed. {METHOD}", pinType);
                throw;
            }
        }
        finally
        {
            // Always release semaphore when we acquired it
            if (acquired)
                _pinSemaphore.Release();
        }
    }

    /// <summary>
    /// Sets up a custom DllImportResolver that may be needed when Pkcs11Interop is running on Linux.
    /// </summary>
    /// <param name="libraryName">This parameter might need to be modified if your distribution uses a different version of libdl.</param>
    private static void SetupCustomDllImportResolver(string libraryName = "libdl.so.2")
    {
        //if (Platform.IsLinux)
        {
            // Pkcs11Interop uses native functions from "libdl.so", but Ubuntu 22.04 and possibly also other distros have "libdl.so.2".
            // Therefore, we need to set up a DllImportResolver to remap "libdl" to "libdl.so.2".
            NativeLibrary.SetDllImportResolver(typeof(Pkcs11InteropFactories).Assembly, (libName, assembly, dllImportSearchPath) =>
            {
                if (libName == "libdl")
                {
                    // Note: This mapping might need to be modified if your distribution uses a different version of libdl.
                    return NativeLibrary.Load(libraryName, assembly, dllImportSearchPath);
                }
                else
                {
                    return NativeLibrary.Load(libName, assembly, dllImportSearchPath);
                }
            });
        }
    }

    /// <summary>
    /// Dispose pattern - release managed resources deterministically.
    /// </summary>
    /// <param name="disposing">true when called from Dispose(); false when called from finalizer.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // dispose managed state
            try
            {
                // Unload will dispose Store, Slot and Token if present
                Unload();
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Error during Unload in Dispose.");
            }

            try
            {
                _pinSemaphore?.Dispose();
            }
            catch
            {
                // swallow
            }
        }

        _disposed = true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        Dispose(disposing: true);
        await ValueTask.CompletedTask;
        GC.SuppressFinalize(this);
    }
}