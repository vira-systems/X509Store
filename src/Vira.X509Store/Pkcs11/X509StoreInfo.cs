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
/// Detailed information about PKCS#11 based X.509 store
/// </summary>
public class X509StoreInfo
{
    /// <summary>
    /// Name of or path to PKCS#11 library
    /// </summary>
    public string LibraryPath { get; }

    /// <summary>
    /// Manufacturer of PKCS#11 library
    /// </summary>
    public string Manufacturer { get; }

    /// <summary>
    /// Description of PKCS#11 library
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Creates new instance of Pkcs11X509StoreInfo class
    /// </summary>
    /// <param name="libraryPath">Name of or path to PKCS#11 library</param>
    /// <param name="libraryInfo">General information about PKCS#11 library (CK_INFO)</param>
    internal X509StoreInfo(string libraryPath, ILibraryInfo libraryInfo)
    {
        ArgumentException.ThrowIfNullOrEmpty(libraryPath);
        ArgumentNullException.ThrowIfNull(libraryInfo);

        LibraryPath = libraryPath;
        Manufacturer = libraryInfo.ManufacturerId;
        Description = libraryInfo.LibraryDescription;
    }
}
