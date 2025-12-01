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

using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Detailed information about PKCS#11 slot representing a logical reader that potentially contains a token
/// </summary>
public class SlotInfo
{
    /// <summary>
    /// Description of the slot
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Manufacturer of the slot
    /// </summary>
    public string Manufacturer { get; }

    /// <summary>
    /// Creates new instance of Pkcs11SlotInfo class
    /// </summary>
    /// <param name="slotInfo">Information about PKCS#11 slot (CK_SLOT_INFO)</param>
    internal SlotInfo(ISlotInfo slotInfo)
    {
        ArgumentNullException.ThrowIfNull(slotInfo, nameof(slotInfo));

        Description = slotInfo.SlotDescription;
        Manufacturer = slotInfo.ManufacturerId;
    }
}
