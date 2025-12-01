/*
 *  Copyright 2017-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// Internal context for Pkcs11Token class
/// </summary>
internal class TokenContext : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    /// <summary>
    /// Detailed information about PKCS#11 token (cryptographic device)
    /// </summary>
    private readonly TokenInfo _tokenInfo;

    /// <summary>
    /// Detailed information about PKCS#11 token (cryptographic device)
    /// </summary>
    internal TokenInfo TokenInfo
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _tokenInfo;
        }
    }

    ///// <summary>
    ///// High level PKCS#11 session that preserves authenticated state of the token
    ///// </summary>
    //private ISession _authenticatedSession;

    ///// <summary>
    ///// High level PKCS#11 session that preserves authenticated state of the token
    ///// </summary>
    //internal ISession AuthenticatedSession
    //{
    //    get
    //    {
    //        ObjectDisposedException.ThrowIf(_disposed, GetType());

    //        return _authenticatedSession;
    //    }
    //    set
    //    {
    //        _authenticatedSession = value;
    //    }
    //}

    ///// <summary>
    ///// Internal context for Pkcs11Slot class
    ///// </summary>
    //private readonly SlotContext _slotContext;

    ///// <summary>
    ///// Internal context for Pkcs11Slot class
    ///// </summary>
    //internal SlotContext SlotContext
    //{
    //    get
    //    {
    //        ObjectDisposedException.ThrowIf(_disposed, GetType());

    //        return _slotContext;
    //    }
    //}

    /// <summary>
    /// Internal context for Pkcs11Slot class
    /// </summary>
    internal SlotContext SlotContext { get; }

    /// <summary>
    /// Creates new instance of Pkcs11TokenContext class
    /// </summary>
    /// <param name="tokenInfo">Detailed information about PKCS#11 token (cryptographic device)</param>
    ///// <param name="authenticatedSession">High level PKCS#11 session that holds authenticated state of the token</param>
    /// <param name="slotContext">Internal context for Pkcs11Slot class</param>
    internal TokenContext(TokenInfo tokenInfo, /*ISession authenticatedSession,*/ SlotContext slotContext)
    {
        _tokenInfo = tokenInfo ?? throw new ArgumentNullException(nameof(tokenInfo));
        //_authenticatedSession = authenticatedSession;
        SlotContext = slotContext ?? throw new ArgumentNullException(nameof(slotContext));
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
                //_authenticatedSession?.Dispose();
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~TokenContext()
    {
        Dispose(false);
    }

    #endregion
}
