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
