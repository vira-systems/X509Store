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
/// Internal context for Pkcs11Slot class
/// </summary>
internal class SlotContext
{
    /// <summary>
    /// High level PKCS#11 slot
    /// </summary>
    internal ISlot Slot { get; }

    /// <summary>
    /// Detailed information about PKCS#11 slot
    /// </summary>
    internal SlotInfo SlotInfo { get; }

    /// <summary>
    /// Internal context for Pkcs11X509Store class
    /// </summary>
    internal X509StoreContext StoreContext { get; }

    /// <summary>
    /// High level PKCS#11 session
    /// </summary>
    internal ISession? Session { get; set; }

    /// <summary>
    /// Creates new instance of Pkcs11SlotContext class
    /// </summary>
    /// <param name="slot">High level PKCS#11 slot</param>
    /// <param name="slotInfo">Detailed information about PKCS#11 slot</param>
    /// <param name="storeContext">Internal context for Pkcs11X509Store class</param>
    internal SlotContext(ISlot slot, SlotInfo slotInfo, X509StoreContext storeContext)
    {
        Slot = slot ?? throw new ArgumentNullException(nameof(slot));
        SlotInfo = slotInfo ?? throw new ArgumentNullException(nameof(slotInfo));
        StoreContext = storeContext ?? throw new ArgumentNullException(nameof(storeContext));
        Session = Slot.OpenSession(Net.Pkcs11Interop.Common.SessionType.ReadOnly);
    }
}
