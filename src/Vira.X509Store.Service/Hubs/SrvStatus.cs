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

namespace Vira.X509Store.Service.Hubs;

/// <summary>
/// Represents the operational status of the service as reported to clients.
/// Values mirror common Windows Service states for consistency.
/// </summary>
public enum SrvStatus
{
    /// <summary>
    /// Service is not installed on the system.
    /// </summary>
    NotInstalled = 0,
    /// <summary>
    /// Service is installed but not running.
    /// </summary>
    Stopped = 1,
    /// <summary>
    /// Service is in the process of starting.
    /// </summary>
    StartPending = 2,
    /// <summary>
    /// Service is in the process of stopping.
    /// </summary>
    StopPending = 3,
    /// <summary>
    /// Service is currently running.
    /// </summary>
    Running = 4,
    /// <summary>
    /// Service is resuming from a paused state.
    /// </summary>
    ContinuePending = 5,
    /// <summary>
    /// Service is entering a paused state.
    /// </summary>
    PausePending = 6,
    /// <summary>
    /// Service is paused (resources held, execution suspended).
    /// </summary>
    Paused = 7,
}
