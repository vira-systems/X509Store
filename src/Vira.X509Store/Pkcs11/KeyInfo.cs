using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// Detailed information about PKCS#11 key that is typically present in the token (cryptographic device).
/// </summary>
public class KeyInfo(IObjectHandle objectHandle, List<IObjectAttribute> objectAttributes, ulong? storageSize)
{
    /// <summary>
    /// Handle of the object;
    /// </summary>
    public IObjectHandle ObjectHandle { get; internal set; } = objectHandle;

    /// <summary>
    /// Cryptoki object attribute list (CK_ATTRIBUTE alternative)
    /// </summary>
    public List<IObjectAttribute> ObjectAttributes { get; internal set; } = objectAttributes;

    /// <summary>
    /// Storage size of the object.
    /// </summary>
    public ulong? StorageSize { get; internal set; } = storageSize;

    /// <summary>
    /// Value of the CKA_CLASS attribute
    /// </summary>
    public ulong CkaClass { get; internal set; } = objectAttributes.Single(e => e.Type == (ulong)CKA.CKA_CLASS).GetValueAsUlong();

    /// <summary>
    /// Value of the CKA_ID attribute
    /// </summary>
    public byte[] CkaId { get; internal set; } = objectAttributes.Single(e => e.Type == (ulong)CKA.CKA_ID).GetValueAsByteArray();

    /// <summary>
    /// Value of the CKA_KEY_TYPE attribute
    /// </summary>
    public ulong CkaKeyType { get; internal set; } = objectAttributes.Single(e => e.Type == (ulong)CKA.CKA_KEY_TYPE).GetValueAsUlong();

    /// <summary>
    /// Value of the CKA_LABEL attribute
    /// </summary>
    public string CkaLabel { get; internal set; } = objectAttributes.Single(e => e.Type == (ulong)CKA.CKA_LABEL).GetValueAsString();

    /// <summary>
    /// Value of the CKA_PRIVATE attribute
    /// </summary>
    public bool CkaPrivate { get; internal set; } = objectAttributes.Single(e => e.Type == (ulong)CKA.CKA_PRIVATE).GetValueAsBool();
}
