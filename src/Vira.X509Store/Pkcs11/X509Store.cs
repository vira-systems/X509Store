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

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// PKCS#11 based read-only X.509 store with certificates and corresponding asymmetric keys
/// </summary>
public class X509Store : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    public bool IsDisposed => _disposed;

    private readonly IPKCS11Library _pkcs11Lib;

    /// <summary>
    /// Internal context for Pkcs11X509Store class
    /// </summary>
    private readonly X509StoreContext _storeContext;

    /// <summary>
    /// Detailed information about PKCS#11 based X.509 store
    /// </summary>
    public X509StoreInfo Info
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _storeContext.StoreInfo;
        }
    }

    /// <summary>
    /// List of available PKCS#11 slots representing logical readers
    /// </summary>
    private readonly List<Slot?>? _slots = null;

    /// <summary>
    /// List of available PKCS#11 slots representing logical readers
    /// </summary>
    public List<Slot?>? Slots
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, GetType());

            return _slots;
        }
    }

    /// <summary>
    /// Creates new instance of Pkcs11X509Store class.
    /// Also loads and initializes unmanaged PCKS#11 library.
    /// </summary>
    /// <param name="libraryPath">Name of or path to PKCS#11 library</param>
    ///// <param name="pinProvider">Provider of PIN codes for PKCS#11 tokens and keys</param>
    /// <param name="slotsType">Type of slots to be obtained by PKCS#11 library</param>
    public X509Store(string libraryPath/*, IPinProvider pinProvider*/, SlotsType slotsType, IPKCS11Library pkcs11Lib)
    {
        ArgumentException.ThrowIfNullOrEmpty(libraryPath);
        //ArgumentNullException.ThrowIfNull(pinProvider);

        _storeContext = GetStoreContext(libraryPath/*, pinProvider*/);
        _slots = GetSlots(slotsType);
        _pkcs11Lib = pkcs11Lib;
    }

    /// <summary>
    /// Constructs internal context for Pkcs11X509Store class
    /// </summary>
    /// <param name="libraryPath">Name of or path to PKCS#11 library</param>
    ///// <param name="pinProvider">Provider of PIN codes for PKCS#11 tokens and keys</param>
    /// <returns>Internal context for Pkcs11X509Store class</returns>
    private static X509StoreContext GetStoreContext(string libraryPath/*, IPinProvider pinProvider*/)
    {
        var factories = new Pkcs11InteropFactories();

        IPkcs11Library? pkcs11Library = null;

        try
        {
            pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);
            var storeInfo = new X509StoreInfo(libraryPath, pkcs11Library.GetInfo());
            return new X509StoreContext(pkcs11Library, storeInfo/*, pinProvider*/);
        }
        catch
        {
            pkcs11Library?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Gets list of available PKCS#11 slots representing logical readers
    /// </summary>
    /// <param name="slotsType">Type of slots to be obtained by PKCS#11 library</param>
    /// <returns>List of available PKCS#11 slots representing logical readers</returns>
    private List<Slot?> GetSlots(SlotsType slotsType)
    {
        var slots = new List<Slot?>();

        foreach (ISlot slot in _storeContext.Pkcs11Library.GetSlotList(slotsType))
        {
            var pkcs11Slot = new Slot(slot, _storeContext, _pkcs11Lib);
            slots.Add(pkcs11Slot);
        }

        return slots;
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
                if (_slots != null)
                {
                    for (int i = 0; i < _slots.Count; i++)
                    {
                        if (_slots[i] != null)
                        {
                            _slots[i]?.Dispose();
                            _slots[i] = null;
                        }
                    }
                }

                _storeContext?.Dispose();
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~X509Store()
    {
        Dispose(false);
    }

    #endregion
}
