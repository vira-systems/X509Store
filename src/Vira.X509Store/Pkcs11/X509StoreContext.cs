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

using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// Internal context for Pkcs11X509Store class
/// </summary>
internal class X509StoreContext : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    /// <summary>
    /// High level PKCS#11 wrapper
    /// </summary>
    private readonly IPkcs11Library _pkcs11Library;

    /// <summary>
    /// High level PKCS#11 wrapper
    /// </summary>
    internal IPkcs11Library Pkcs11Library
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _pkcs11Library;
        }
    }

    /// <summary>
    /// Detailed information about PKCS#11 based X.509 store
    /// </summary>
    private readonly X509StoreInfo _storeInfo;

    /// <summary>
    /// Detailed information about PKCS#11 based X.509 store
    /// </summary>
    internal X509StoreInfo StoreInfo
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _storeInfo;
        }
    }

    ///// <summary>
    ///// Provider of PIN codes for PKCS#11 tokens and keys
    ///// </summary>
    //private readonly IPinProvider _pinProvider;

    ///// <summary>
    ///// Provider of PIN codes for PKCS#11 tokens and keys
    ///// </summary>
    //internal IPinProvider PinProvider
    //{
    //    get
    //    {
    //        ObjectDisposedException.ThrowIf(_disposed, GetType());

    //        return _pinProvider;
    //    }
    //}

    /// <summary>
    /// Creates new instance of Pkcs11X509StoreContext class
    /// </summary>
    /// <param name="pkcs11Library">High level PKCS#11 wrapper</param>
    /// <param name="storeInfo">Detailed information about PKCS#11 based X.509 store</param>
    ///// <param name="pinProvider">Provider of PIN codes for PKCS#11 tokens and keys</param>
    internal X509StoreContext(IPkcs11Library pkcs11Library, X509StoreInfo storeInfo/*, IPinProvider pinProvider*/)
    {
        _pkcs11Library = pkcs11Library ?? throw new ArgumentNullException(nameof(pkcs11Library));
        _storeInfo = storeInfo ?? throw new ArgumentNullException(nameof(storeInfo));
        //_pinProvider = pinProvider ?? throw new ArgumentNullException(nameof(pinProvider));
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
                _pkcs11Library?.Dispose();
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~X509StoreContext()
    {
        Dispose(false);
    }

    #endregion
}
