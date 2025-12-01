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

using Vira.X509Store.Service.Pkcs11;
using Vira.X509Store.Service.Services;

namespace Vira.X509Store.Service.Hubs;

/// <summary>
/// Contract for client callbacks invoked by the token SignalR hub. Each method delivers
/// an asynchronous result wrapper (<see cref="HubResult{T}"/>) for a specific operation
/// (PIN retrieval, cryptographic actions, CMS, CSR, import/export, status queries).
/// </summary>
public interface ITokenHub
{
    /// <summary>
    /// Sends the result of an operation that retrieves the key PIN (user PIN for private key use).
    /// </summary>
    /// <returns>Task representing the asynchronous send.</returns>
    Task<PinResult> GetKeyPin();

    /// <summary>
    /// Sends the result of an operation that retrieves the token PIN (login/authentication PIN).
    /// </summary>
    /// <returns>Task representing the asynchronous send.</returns>
    Task<PinResult> GetTokenPin();

    /// <summary>
    /// Sends current service/device status information (custom status payload).
    /// </summary>
    /// <param name="result">Result wrapper containing service status.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task DastyarStatus(HubResult<SrvStatus> result);

    /// <summary>
    /// Sends PKCS#11 token information (manufacturer, model, serial, etc.).
    /// </summary>
    /// <param name="result">Result wrapper containing token info or null.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task TokenInfo(HubResult<TokenInfo?> result);

    /// <summary>
    /// Sends list of supported mechanisms with their capabilities (sign, encrypt, etc.).
    /// </summary>
    /// <param name="result">Result wrapper containing mechanism info collection.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task MechanismInfos(HubResult<IEnumerable<MechanismInfo>?> result);

    /// <summary>
    /// Sends a list of available certificates found in the requested store(s).
    /// </summary>
    /// <param name="result">Result wrapper containing certificate details collection.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task CertificateList(HubResult<IEnumerable<CertificateDetails>?> result);

    /// <summary>
    /// Sends the thumbprint or identifier of the currently selected certificate.
    /// </summary>
    /// <param name="result">Result wrapper containing selected certificate identifier.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task SelectedCertificate(HubResult<string?> result);

    /// <summary>
    /// Sends the result of an encryption operation (raw encrypted bytes).
    /// </summary>
    /// <param name="result">Result wrapper containing encrypted data.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task Encrypt(HubResult<byte[]?> result);

    /// <summary>
    /// Sends the result of a decryption operation (raw plaintext bytes).
    /// </summary>
    /// <param name="result">Result wrapper containing decrypted data.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task Decrypt(HubResult<byte[]?> result);

    /// <summary>
    /// Sends the result of a digital signature operation (signature bytes).
    /// </summary>
    /// <param name="result">Result wrapper containing signature.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task Sign(HubResult<byte[]?> result);

    /// <summary>
    /// Sends the result of a signature verification operation (true if valid).
    /// </summary>
    /// <param name="result">Result wrapper containing verification outcome.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task Verify(HubResult<bool?> result);

    /// <summary>
    /// Sends the result of a CMS encryption operation (encrypted CMS bytes).
    /// </summary>
    /// <param name="result">Result wrapper containing CMS encrypted data.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task CmsEncrypt(HubResult<byte[]?> result);

    /// <summary>
    /// Sends the result of a CMS decryption operation (decrypted content bytes).
    /// </summary>
    /// <param name="result">Result wrapper containing CMS decrypted data.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task CmsDecrypt(HubResult<byte[]?> result);

    /// <summary>
    /// Sends the result of a CMS signing operation (signed CMS bytes).
    /// </summary>
    /// <param name="result">Result wrapper containing signed CMS data.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task CmsSign(HubResult<byte[]?> result);

    /// <summary>
    /// Sends the result of a CMS verification operation (certificate list, original data, validity flag).
    /// </summary>
    /// <param name="result">Result wrapper containing verification details.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task CmsVerify(HubResult<CmsVerifyResult?> result);

    /// <summary>
    /// Sends a PKCS#10 CSR (DER form) generation result.
    /// </summary>
    /// <param name="result">Result wrapper containing DER-encoded CSR details.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task CSR(HubResult<CsrResult<byte[]>?> result);

    /// <summary>
    /// Sends a PKCS#10 CSR (PEM form) generation result.
    /// </summary>
    /// <param name="result">Result wrapper containing PEM-encoded CSR details.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task CSR(HubResult<CsrResult<string>?> result);

    /// <summary>
    /// Sends the result of a certificate import operation (true on success).
    /// </summary>
    /// <param name="result">Result wrapper indicating import success.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task Import(HubResult<bool?> result);

    /// <summary>
    /// Sends the result of a certificate export operation (raw certificate bytes).
    /// </summary>
    /// <param name="result">Result wrapper containing exported certificate.</param>
    /// <returns>Task representing the asynchronous send.</returns>
    Task Export(HubResult<byte[]?> result);
}
