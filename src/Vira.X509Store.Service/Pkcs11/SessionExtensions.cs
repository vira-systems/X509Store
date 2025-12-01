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

internal static class SessionExtensions
{

    /// <summary>
    /// Checks whether the user is authenticated and can authenticate.
    /// </summary>
    /// <param name="session">Session to be checked</param>
    /// <returns>Returns a <see cref="SessionInfo"/> indicating the authentication status of the session.</returns>
    public static SessionInfo IsAuthenticated(this ISession session)
    {
        ISessionInfo sessionInfo = session.GetSessionInfo();
        return sessionInfo.State switch
        {
            CKS.CKS_RO_PUBLIC_SESSION or CKS.CKS_RW_PUBLIC_SESSION => new SessionInfo
            {
                CanAuthenticate = true,
                IsAuthenticated = false,
            },
            CKS.CKS_RO_USER_FUNCTIONS or CKS.CKS_RW_USER_FUNCTIONS => new SessionInfo
            {
                CanAuthenticate = false,
                IsAuthenticated = true,
            },
            CKS.CKS_RW_SO_FUNCTIONS => new SessionInfo
            {
                CanAuthenticate = false,
                IsAuthenticated = false,
            },
            _ => throw new NotSupportedException($"Session state {sessionInfo.State} is not supported"),
        };
    }
}
