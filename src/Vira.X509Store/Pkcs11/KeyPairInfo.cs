namespace Vira.X509Store.Pkcs11;

/// <summary>
/// Detailed information about PKCS#11 key pair that are typically present in the token (cryptographic device).
/// </summary>
public class KeyPairInfo
{
    ///// <summary>
    ///// Gets the label of the key pair
    ///// </summary>
    //public string Label { get; internal set; }

    ///// <summary>
    ///// Gets the subject public key information
    ///// </summary>
    //public byte[] SubjectPublicKeyInfo { get; internal set; }

    /// <summary>
    /// Gets the private key information
    /// </summary>
    public KeyInfo? PrivateKeyInfo { get; internal set; }

    /// <summary>
    /// Gets the public key information
    /// </summary>
    public KeyInfo? PublicKeyInfo { get; internal set; }
}
