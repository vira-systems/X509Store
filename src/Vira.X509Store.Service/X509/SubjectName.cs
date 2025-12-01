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

namespace Vira.X509Store.Service.X509;

/// <summary>
/// Represents a single subject distinguished name (DN) component as a name/value pair
/// and exposes an ordering value derived from <see cref="SubjectDns"/> for sorting.
/// </summary>
internal class SubjectName
{
    /// <summary>
    /// Gets or sets the DN attribute name (e.g., "CN", "O", "OU", "C").
    /// The value should map to a member of <see cref="SubjectDns"/> (case-insensitive).
    /// </summary>
    public string Name { get; set; } = null!;

    /// <summary>
    /// Gets or sets the DN attribute value corresponding to <see cref="Name"/>.
    /// </summary>
    public string Value { get; set; } = null!;

    /// <summary>
    /// Gets the sort order for this DN component based on the <see cref="SubjectDns"/> enum.
    /// Used to produce a canonical ordering of DN fields. Parsing is case-insensitive.
    /// </summary>
    /// <remarks>
    /// Will throw if <see cref="Name"/> does not match a <see cref="SubjectDns"/> member.
    /// </remarks>
    public int Order => (int)Enum.Parse<SubjectDns>(Name, true);
}
