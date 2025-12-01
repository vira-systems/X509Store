using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Pkcs11;

public class MechanismInfo
{
    public MechanismInfo(string error)
    {
        Error = error;
    }

    internal MechanismInfo(CKM mechanism, IMechanismInfo mechanismInfo)
    {
        Mechanism = mechanism;
        MinKeySize = mechanismInfo.MinKeySize;
        MaxKeySize = mechanismInfo.MaxKeySize;
        Flags = mechanismInfo.MechanismFlags.Flags;
        PerformedInHW = mechanismInfo.MechanismFlags.Hw;
        Encrypt = mechanismInfo.MechanismFlags.Encrypt;
        Decrypt = mechanismInfo.MechanismFlags.Decrypt;
        Digest = mechanismInfo.MechanismFlags.Digest;
        Sign = mechanismInfo.MechanismFlags.Sign;
        SignRecover = mechanismInfo.MechanismFlags.SignRecover;
        Verify = mechanismInfo.MechanismFlags.Verify;
        VerifyRecover = mechanismInfo.MechanismFlags.VerifyRecover;
        GenerateKey = mechanismInfo.MechanismFlags.Generate;
        GenerateKeyPair = mechanismInfo.MechanismFlags.GenerateKeyPair;
        KeyWrapping = mechanismInfo.MechanismFlags.Wrap;
        KeyUnwrapping = mechanismInfo.MechanismFlags.Unwrap;
        KeyDerivation = mechanismInfo.MechanismFlags.Derive;
        HasExtension = mechanismInfo.MechanismFlags.Extension;
        EcOverFp = mechanismInfo.MechanismFlags.EcFp;
        EcOverF2m = mechanismInfo.MechanismFlags.EcF2m;
        EcEcParameters = mechanismInfo.MechanismFlags.EcEcParameters;
        EcNamedCurve = mechanismInfo.MechanismFlags.EcNamedCurve;
        EcPointCompress = mechanismInfo.MechanismFlags.EcCompress;
        EcPointUncompress = mechanismInfo.MechanismFlags.EcUncompress;
    }

    public CKM Mechanism { get; internal set; }

    public string MechanismName => Mechanism.ToString();

    public ulong MinKeySize { get; internal set; }

    public ulong MaxKeySize { get; internal set; }

    public ulong Flags { get; internal set; }

    public bool PerformedInHW { get; internal set; }

    public bool Encrypt { get; internal set; }

    public bool Decrypt { get; internal set; }

    public bool Digest { get; internal set; }

    public bool Sign { get; internal set; }

    public bool SignRecover { get; internal set; }

    public bool Verify { get; internal set; }

    public bool VerifyRecover { get; internal set; }

    public bool GenerateKey { get; internal set; }

    public bool GenerateKeyPair { get; internal set; }

    public bool KeyWrapping { get; internal set; }

    public bool KeyUnwrapping { get; internal set; }

    public bool KeyDerivation { get; internal set; }

    public bool HasExtension { get; internal set; }

    public bool EcOverFp { get; internal set; }

    public bool EcOverF2m { get; internal set; }

    public bool EcEcParameters { get; internal set; }

    public bool EcNamedCurve { get; internal set; }

    public bool EcPointCompress { get; internal set; }

    public bool EcPointUncompress { get; internal set; }

    public string? Error { get; internal set; }
}
