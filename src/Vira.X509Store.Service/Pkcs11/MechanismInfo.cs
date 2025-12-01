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

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Describes a PKCS#11 mechanism and its capabilities as reported by the token.
/// Populated from <see cref="IMechanismInfo"/> and exposed to clients for feature discovery.
/// </summary>
public class MechanismInfo
{
    /// <summary>
    /// Creates a mechanism info that only carries an error message (used when
    /// mechanism discovery fails or no usable slot is available).
    /// </summary>
    /// <param name="error">Human-readable error message.</param>
    public MechanismInfo(string error)
    {
        Error = error;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="MechanismInfo"/> from PKCS#11 mechanism data.
    /// </summary>
    /// <param name="mechanism">Mechanism type identifier (CKM).</param>
    /// <param name="mechanismInfo">Mechanism info returned by the token.</param>
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

    /// <summary>
    /// Mechanism type identifier (CKM).
    /// </summary>
    public CKM Mechanism { get; internal set; }

    /// <summary>
    /// String representation of <see cref="Mechanism"/>.
    /// </summary>
    public string MechanismName => Mechanism.ToString();

    /// <summary>
    /// Minimum key size supported by this mechanism.
    /// </summary>
    public ulong MinKeySize { get; internal set; }

    /// <summary>
    /// Maximum key size supported by this mechanism.
    /// </summary>
    public ulong MaxKeySize { get; internal set; }

    /// <summary>
    /// Raw mechanism flags bitmask as reported by the token.
    /// </summary>
    public ulong Flags { get; internal set; }

    /// <summary>
    /// Indicates whether operations are performed in hardware (HW flag).
    /// </summary>
    public bool PerformedInHW { get; internal set; }

    /// <summary>
    /// Indicates support for encryption.
    /// </summary>
    public bool Encrypt { get; internal set; }

    /// <summary>
    /// Indicates support for decryption.
    /// </summary>
    public bool Decrypt { get; internal set; }

    /// <summary>
    /// Indicates support for digest (hash) computation.
    /// </summary>
    public bool Digest { get; internal set; }

    /// <summary>
    /// Indicates support for signature generation.
    /// </summary>
    public bool Sign { get; internal set; }

    /// <summary>
    /// Indicates support for signature generation with recovery.
    /// </summary>
    public bool SignRecover { get; internal set; }

    /// <summary>
    /// Indicates support for signature verification.
    /// </summary>
    public bool Verify { get; internal set; }

    /// <summary>
    /// Indicates support for signature verification with recovery.
    /// </summary>
    public bool VerifyRecover { get; internal set; }

    /// <summary>
    /// Indicates support for symmetric key generation.
    /// </summary>
    public bool GenerateKey { get; internal set; }

    /// <summary>
    /// Indicates support for asymmetric key pair generation.
    /// </summary>
    public bool GenerateKeyPair { get; internal set; }

    /// <summary>
    /// Indicates support for key wrapping.
    /// </summary>
    public bool KeyWrapping { get; internal set; }

    /// <summary>
    /// Indicates support for key unwrapping.
    /// </summary>
    public bool KeyUnwrapping { get; internal set; }

    /// <summary>
    /// Indicates support for key derivation.
    /// </summary>
    public bool KeyDerivation { get; internal set; }

    /// <summary>
    /// Indicates support for non-standard extensions.
    /// </summary>
    public bool HasExtension { get; internal set; }

    /// <summary>
    /// Indicates elliptic curve over prime field (EC over Fp) support.
    /// </summary>
    public bool EcOverFp { get; internal set; }

    /// <summary>
    /// Indicates elliptic curve over binary field (EC over F2m) support.
    /// </summary>
    public bool EcOverF2m { get; internal set; }

    /// <summary>
    /// Indicates support for EC parameters provided explicitly.
    /// </summary>
    public bool EcEcParameters { get; internal set; }

    /// <summary>
    /// Indicates support for named EC curves.
    /// </summary>
    public bool EcNamedCurve { get; internal set; }

    /// <summary>
    /// Indicates support for EC point compression.
    /// </summary>
    public bool EcPointCompress { get; internal set; }

    /// <summary>
    /// Indicates support for EC point uncompression.
    /// </summary>
    public bool EcPointUncompress { get; internal set; }

    /// <summary>
    /// Optional error message when mechanism information could not be retrieved.
    /// </summary>
    public string? Error { get; internal set; }
}
