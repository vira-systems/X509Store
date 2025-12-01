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

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// Public numeric error codes representing mapped PKCS#11 conditions returned to clients.
/// These codes are used in hub/API responses to enable client-side branching and localization.
/// </summary>
public static class Pkcs11ErrorCodes
{
    /// <summary>
    /// Unknown/unspecified error condition.
    /// </summary>
    public const int Unknown = 0;

    /// <summary>
    /// Invalid user type for login (e.g., SO vs user mismatch).
    /// </summary>
    public const int UserTypeInvalid = 1001;

    /// <summary>
    /// The provided PIN is incorrect.
    /// </summary>
    public const int PinIncorrect = 1002;

    /// <summary>
    /// The PIN is locked; user action is required to unlock/reset.
    /// </summary>
    public const int PinLocked = 1003;

    /// <summary>
    /// The user is already logged in on the token/session.
    /// </summary>
    public const int UserAlreadyLoggedIn = 1004;

    /// <summary>
    /// The user is not logged in; login is required for the operation.
    /// </summary>
    public const int UserNotLoggedIn = 1005;

    /// <summary>
    /// The user PIN has not been initialized on the token.
    /// </summary>
    public const int UserPinNotInitialized = 1006;

    /// <summary>
    /// Generic device error reported by the token/library/driver.
    /// </summary>
    public const int DeviceError = 1007;
}