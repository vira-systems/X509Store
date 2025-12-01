using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Pkcs11;

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
