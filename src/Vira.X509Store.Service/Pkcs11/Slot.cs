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
using System.Xml.Xsl;
using ISession = Net.Pkcs11Interop.HighLevelAPI.ISession;

namespace Vira.X509Store.Service.Pkcs11;

/// <summary>
/// PKCS#11 slot representing a logical reader that potentially contains a token
/// </summary>
public class Slot : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    public bool IsDisposed => _disposed;

    private readonly IPKCS11Library _pkcs11Lib;

    /// <summary>
    /// Internal context for Pkcs11Slot class
    /// </summary>
    private readonly SlotContext _slotContext;

    /// <summary>
    /// Returns a previously opened read-only session or opens a new session.
    /// </summary>
    private ISession? Session
    {
        get
        {
            //ObjectDisposedException.ThrowIf(_disposed, GetType());
            return _slotContext.Session;
        }
        set { _slotContext.Session = value; }
    }

    /// <summary>
    /// Detailed information about PKCS#11 slot representing a logical reader
    /// </summary>
    public SlotInfo Info
    {
        get
        {
            //if (_disposed)
            //    throw new ObjectDisposedException(GetType().FullName);
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _slotContext.SlotInfo;
        }
    }

    /// <summary>
    /// PKCS#11 token (cryptographic device) that is typically present in the slot
    /// </summary>
    private Token? _token;

    /// <summary>
    /// PKCS#11 token (cryptographic device) that is typically present in the slot
    /// </summary>
    public Token? Token
    {
        get
        {
            //if (_disposed)
            //    throw new ObjectDisposedException(GetType().FullName);
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _token;
        }
    }

    /// <summary>
    /// Logs into the session using the user PIN.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the session is not opened.</exception>
    public void LoginSession(string? pin = null)
    {
        //if (_disposed)
        //    throw new ObjectDisposedException(GetType().FullName);
        ObjectDisposedException.ThrowIf(_disposed, GetType());
        if (Session == null)
            throw new InvalidOperationException("Session is not opened. Use OpenSession method first.");

        var sessionInfo = Session.IsAuthenticated();
        if (sessionInfo.CanAuthenticate && !sessionInfo.IsAuthenticated)
        {
            _token ??= GetToken();
            if (_token == null)
                throw new NullReferenceException("Token is not present.");

            //pin ??= PinProviderUtils.GetTokenPin(_slotContext, Token!.Info.HasProtectedAuthenticationPath);
            if (string.IsNullOrEmpty(pin))
            {
                var pinResult = _pkcs11Lib.RequestTokenPinAsync().GetAwaiter().GetResult();
                pin = pinResult.Pin;
            }
            Session.Login(CKU.CKU_USER, pin);
        }
    }

    /// <summary>
    /// Logs out of the session if it is currently authenticated.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the session is not opened.</exception>
    public void LogoutSession()
    {
        //if (_disposed)
        //    throw new ObjectDisposedException(GetType().FullName);
        ObjectDisposedException.ThrowIf(_disposed, GetType());
        if (Session == null)
            throw new InvalidOperationException("Session is not opened. Use OpenSession method first.");

        var sessionInfo = Session.IsAuthenticated();
        if (sessionInfo.IsAuthenticated)
        {
            Session.Logout();
        }
    }

    /// <summary>
    /// Opens a session with the specified session type.
    /// </summary>
    /// <param name="sessionType">The type of session to open. Defaults to ReadOnly.</param>
    /// <returns>An instance of ISession representing the opened session.</returns>
    public ISession OpenSession(SessionType sessionType = SessionType.ReadOnly)
    {
        ObjectDisposedException.ThrowIf(_disposed, GetType());

        Session ??= _slotContext.Slot.OpenSession(sessionType);

        return Session;
    }

    /// <summary>
    /// Opens new session with the specified session type.
    /// </summary>
    /// <param name="sessionType">The type of session to open. Defaults to ReadOnly.</param>
    /// <returns>An instance of ISession representing the opened session.</returns>
    public ISession OpenNewSession(SessionType sessionType = SessionType.ReadOnly)
    {
        ObjectDisposedException.ThrowIf(_disposed, GetType());

        return _slotContext.Slot.OpenSession(sessionType);
    }

    public IEnumerable<MechanismInfo> GetMechanismInfos()
    {
        var mechanisms = new List<MechanismInfo>();
        foreach (var mechanism in _slotContext.Slot.GetMechanismList())
        {
            var mechanismInfo = _slotContext.Slot.GetMechanismInfo(mechanism);
            mechanisms.Add(new MechanismInfo(mechanism, mechanismInfo));
        }
        return mechanisms;
    }

    /// <summary>
    /// Checks if the specified cryptographic mechanism is supported by the PKCS#11 slot.
    /// </summary>
    /// <param name="mechanism">The cryptographic mechanism to check.</param>
    /// <returns>True if the mechanism is supported; otherwise, false.</returns>
    public bool IsSupported(CKM mechanism)
    {
        return _slotContext.Slot.GetMechanismInfo(mechanism).MechanismFlags.GenerateKeyPair;
    }

    /// <summary>
    /// Creates new instance of Pkcs11Slot class
    /// </summary>
    /// <param name="slot">High level PKCS#11 slot</param>
    /// <param name="storeContext">Internal context for Pkcs11X509Store class</param>
    internal Slot(ISlot slot, X509StoreContext storeContext, IPKCS11Library pkcs11Lib)
    {
        //if (slot == null)
        //    throw new ArgumentNullException(nameof(slot));

        //if (storeContext == null)
        //    throw new ArgumentNullException(nameof(storeContext));

        ArgumentNullException.ThrowIfNull(slot, nameof(slot));
        ArgumentNullException.ThrowIfNull(storeContext, nameof(storeContext));

        _pkcs11Lib = pkcs11Lib;
        _slotContext = GetSlotContext(slot, storeContext);
        _token = GetToken();
    }

    internal IMechanismInfo GetMechanismInfo(CKM mechanism)
    {
        return _slotContext.Slot.GetMechanismInfo(mechanism);
    }

    /// <summary>
    /// Constructs internal context for Pkcs11Slot class
    /// </summary>
    /// <param name="slot">High level PKCS#11 slot</param>
    /// <param name="storeContext">Internal context for Pkcs11X509Store class</param>
    /// <returns>Internal context for Pkcs11Slot class</returns>
    private static SlotContext GetSlotContext(ISlot slot, X509StoreContext storeContext)
    {
        var slotInfo = new SlotInfo(slot.GetSlotInfo());
        return new SlotContext(slot, slotInfo, storeContext);
    }

    /// <summary>
    /// Gets PKCS#11 token (cryptographic device) that is typically present in the slot
    /// </summary>
    /// <returns>PKCS#11 token (cryptographic device) that is typically present in the slot</returns>
    private Token? GetToken()
    {
        if (!_slotContext.Slot.GetSlotInfo().SlotFlags.TokenPresent)
            return null;

        try
        {
            return new Token(_slotContext, _pkcs11Lib);
        }
        catch (Pkcs11Exception ex)
        {
            if (ex.RV == CKR.CKR_TOKEN_NOT_RECOGNIZED || ex.RV == CKR.CKR_TOKEN_NOT_PRESENT)
                return null;

            throw;
        }
    }

    #region IDisposable

    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed objects
                if (Session != null)
                {
                    Session.Dispose();
                    Session = null;
                }
                if (_token != null)
                {
                    _token.Dispose();
                    _token = null;
                }
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~Slot()
    {
        Dispose(false);
    }

    #endregion
}
