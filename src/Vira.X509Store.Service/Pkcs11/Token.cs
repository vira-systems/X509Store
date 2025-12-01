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
/// PKCS#11 token (cryptographic device) that is typically present in the slot
/// </summary>
public class Token : IDisposable
{
    /// <summary>
    /// Creates new instance of Pkcs11Token class
    /// </summary>
    /// <param name="slotContext">Internal context for Pkcs11Slot class</param>
    internal Token(SlotContext slotContext, IPKCS11Library pkcs11Lib)
    {
        ArgumentNullException.ThrowIfNull(slotContext, nameof(slotContext));

        _pkcs11Lib = pkcs11Lib;
        _tokenContext = GetTokenContext(slotContext);
        // Note: _certificates are loaded on first access
    }

    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    public bool IsDisposed => _disposed;

    private readonly IPKCS11Library _pkcs11Lib;

    /// <summary>
    /// private context for Pkcs11Token class
    /// </summary>
    private readonly TokenContext _tokenContext;

    /// <summary>
    /// Internal context for Pkcs11Token class
    /// </summary>
    internal TokenContext TokenContext => _tokenContext;

    /// <summary>
    /// Detailed information about PKCS#11 token (cryptographic device)
    /// </summary>
    public TokenInfo Info
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _tokenContext.TokenInfo;
        }
    }

    /// <summary>
    /// Certificates present on token.
    /// </summary>
    private List<X509Certificate>? _certificates;

    /// <summary>
    /// Certificates present on token.
    /// This property may use provider of PIN codes (IPinProvider) on access.
    /// </summary>
    public List<X509Certificate> Certificates
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            if (_certificates == null)
                ReloadCertificates();

            return _certificates!;
        }
    }

    /// <summary>
    /// Returns a previously opened read-only session or opens a new session.
    /// </summary>
    public ISession? Session
    {
        get
        {
            //ObjectDisposedException.ThrowIf(_disposed, GetType());
            return _tokenContext.SlotContext.Session;
        }
        internal set { _tokenContext.SlotContext.Session = value; }
    }

    /// <summary>
    /// Reloads certificates present on token.
    /// This method may use provider of PIN codes (IPinProvider).
    /// </summary>
    public void ReloadCertificates()
    {
        ObjectDisposedException.ThrowIf(_disposed, GetType());

        _certificates = FindCertificates();
    }

    /// <summary>
    /// Constructs internal context for Pkcs11Token class
    /// </summary>
    /// <param name="slotContext">Internal context for Pkcs11Slot class</param>
    /// <returns>Internal context for Pkcs11Token class</returns>
    private static TokenContext GetTokenContext(SlotContext slotContext)
    {
        var tokenInfo = new TokenInfo(slotContext.Slot.GetTokenInfo());
        if (!tokenInfo.Initialized)
            throw new InvalidOperationException("Token is not initialized.");

        //var masterSession = slotContext.Slot.OpenSession(SessionType.ReadOnly);
        return new TokenContext(tokenInfo, /*masterSession, */slotContext);
    }

    /// <summary>
    /// Finds all X.509 certificates present on token
    /// </summary>
    /// <returns>All X.509 certificates present on token</returns>
    private List<X509Certificate> FindCertificates()
    {
        var certificates = new List<X509Certificate>();

        if (_tokenContext.TokenInfo.Initialized)
        {
            Session ??= _tokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly);
            var factory = Session.Factories.ObjectAttributeFactory;
            var searchTemplate = new List<IObjectAttribute>()
            {
                factory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                factory.Create(CKA.CKA_TOKEN, true),
                factory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            };

            foreach (IObjectHandle certHandle in Session.FindAllObjects(searchTemplate))
            {
                var pkcs11cert = new X509Certificate(certHandle, _tokenContext, _pkcs11Lib);
                certificates.Add(pkcs11cert);
            }
        }

        return certificates;
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
                //if (Session != null)
                //{
                //    Session.Dispose();
                //    Session = null;
                //}
                _tokenContext?.Dispose();
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~Token()
    {
        Dispose(false);
    }

    #endregion
}
