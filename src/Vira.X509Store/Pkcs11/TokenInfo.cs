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
using System.Text.Json.Serialization;

namespace Vira.X509Store.Pkcs11;

/// <summary>
/// Detailed information about PKCS#11 token (cryptographic device) that is typically present in the slot
/// </summary>
public class TokenInfo
{
    /// <summary>
    /// Manufacturer of the token
    /// </summary>
    [JsonPropertyName("manufacturer")]
    public string Manufacturer { get; }

    /// <summary>
    /// Model of the token
    /// </summary>
    [JsonPropertyName("model")]
    public string Model { get; }

    /// <summary>
    /// Serial number of the token
    /// </summary>
    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; }

    /// <summary>
    /// Label of the token
    /// </summary>
    [JsonPropertyName("label")]
    public string Label { get; }

    /// <summary>
    /// Flag indicating whether token has a protected authentication path (e.g. pin pad) whereby a user can log into the token without passing a PIN through the API
    /// </summary>
    [JsonPropertyName("hasProtectedAuthenticationPath")]
    public bool HasProtectedAuthenticationPath { get; }

    /// <summary>
    /// Flag indicating whether token has been initialized and is usable
    /// </summary>
    [JsonPropertyName("initialized")]
    public bool Initialized { get; }

    /// <summary>
    /// Creates new instance of Pkcs11TokenInfo class
    /// </summary>
    /// <param name="tokenInfo">Information about PKCS#11 token (CK_TOKEN_INFO)</param>
    internal TokenInfo(ITokenInfo tokenInfo)
    {
        ArgumentNullException.ThrowIfNull(tokenInfo);

        Manufacturer = tokenInfo.ManufacturerId;
        Model = tokenInfo.Model;
        SerialNumber = tokenInfo.SerialNumber;
        Label = tokenInfo.Label;
        HasProtectedAuthenticationPath = tokenInfo.TokenFlags.ProtectedAuthenticationPath;
        Initialized = tokenInfo.TokenFlags.TokenInitialized;
    }
}
