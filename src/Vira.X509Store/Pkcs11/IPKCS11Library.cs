using Microsoft.AspNetCore.SignalR;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1.X509;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Vira.Caching.Services;
//using Vira.X509Store.Service.Hubs;

namespace Vira.X509Store.Pkcs11;

public interface IPKCS11Library
{
    internal const int MillisecondsTimeout = 30_000;

    bool IsLoaded { get; }

    CspInfo? ConnectedDeviceCSP { get; }

    Slot? UsableSlot { get; }

    Token? Token { get; }

    X509Store? Store { get; }

    IEnumerable<CspInfo> SupportedProviders { get; set; }

    SecureString? KeyPin { get; set; }

    SecureString? TokenPin { get; set; }

    ICacheService? Cache { get; }

    //IHubContext<TokenHub>? Hub { get; }
    IHubContext? Hub { get; }

    void Load(CspInfo? cspInfo, SlotsType slotsType = SlotsType.WithTokenPresent);

    void Unload();

    void LoadConnectedDevice();

    void GenerateEcCsrDER(ISession session,
                          X500DistinguishedName subjectDn,
                          string? label,
                          CKM mechanismType,
                          EllipticCurveFlags ellipticCurve,
                          X509Extensions extensions,
                          out byte[] keyId,
                          out byte[] csrDER);

    void GenerateEcCsrPEM(ISession session,
                          X500DistinguishedName subjectDn,
                          string? label,
                          CKM mechanismType,
                          EllipticCurveFlags ellipticCurve,
                          X509Extensions extensions,
                          out byte[] keyId,
                          out string csrPEM);

    void GenerateEcKeyPair(ISession session,
                           EllipticCurveFlags ellipticCurve,
                           string? label,
                           out KeyInfo publicKeyInfo,
                           out KeyInfo privateKeyInfo,
                           out byte[] subjectPublicKeyInfo,
                           out byte[] ckaId);

    void GenerateRsaCsrDER(ISession session,
                           X500DistinguishedName subjectDn,
                           string? label,
                           CKM mechanismType,
                           ulong keySize,
                           X509Extensions extensions,
                           out byte[] keyId,
                           out byte[] csrDER);

    void GenerateRsaCsrPEM(ISession session,
                           X500DistinguishedName subjectDn,
                           string? label,
                           CKM mechanismType,
                           ulong keySize,
                           X509Extensions extensions,
                           out byte[] keyId,
                           out string csrPEM);

    void GenerateRsaKeyPair(ISession session,
                            ulong keyLength,
                            string? label,
                            out KeyInfo publicKeyInfo,
                            out KeyInfo privateKeyInfo,
                            out byte[] subjectPublicKeyInfo,
                            out byte[] ckaId);

    Task<ISession> CreateAuthenticatedSessionAsync(SessionType sessionType = SessionType.ReadWrite,
                                                   int millisecondsTimeout = MillisecondsTimeout,
                                                   CancellationToken cancellationToken = default);

    Task LoginSessionAsync(int millisecondsTimeout = MillisecondsTimeout, CancellationToken cancellationToken = default);

    Task<PinResult> RequestKeyPinAsync(int millisecondsTimeout = MillisecondsTimeout, CancellationToken cancellationToken = default);

    Task<PinResult> RequestTokenPinAsync(int millisecondsTimeout = MillisecondsTimeout, CancellationToken cancellationToken = default);
}
