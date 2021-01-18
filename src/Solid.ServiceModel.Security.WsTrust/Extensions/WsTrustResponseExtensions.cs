using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public static class WsTrustResponseExtensions
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    {
        /// <summary>
        /// Gets all <see cref="SecurityToken"/>s that are in the <paramref name="response"/>.
        /// </summary>
        /// <param name="response">An <see cref="WsTrustResponse"/> instance.</param>
        /// <returns>An <see cref="IEnumerable{T}"/> of <see cref="SecurityToken"/>.</returns>
        public static IEnumerable<SecurityToken> GetRequestedSecurityTokens(this WsTrustResponse response)
            => response?.RequestSecurityTokenResponseCollection?.Select(r => r.RequestedSecurityToken?.SecurityToken) ?? Enumerable.Empty<SecurityToken>();

        /// <summary>
        /// Gets a single <see cref="SecurityToken"/> that is in the <paramref name="response"/>.
        /// <para>If more than one <see cref="SecurityToken"/> is contained withing the <paramref name="response"/>, an exception will be thrown.</para>
        /// </summary>
        /// <param name="response">An <see cref="WsTrustResponse"/> instance.</param>
        /// <returns>A <see cref="SecurityToken"/> instance.</returns>
        public static SecurityToken GetRequestedSecurityToken(this WsTrustResponse response)
            => response.GetRequestedSecurityTokens().Single();

        /// <summary>
        /// Gets all security token <see cref="XmlElement"/>s that are in the <paramref name="response"/>.
        /// </summary>
        /// <param name="response">An <see cref="WsTrustResponse"/> instance.</param>
        /// <returns>An <see cref="IEnumerable{T}"/> of <see cref="XmlElement"/>.</returns>
        public static IEnumerable<XmlElement> GetRequestedSecurityTokenElements(this WsTrustResponse response)
            => response?.RequestSecurityTokenResponseCollection?.Select(r => r.RequestedSecurityToken?.TokenElement) ?? Enumerable.Empty<XmlElement>();

        /// <summary>
        /// Gets a single security token <see cref="XmlElement"/> that is in the <paramref name="response"/>.
        /// <para>If more than one security token is contained withing the <paramref name="response"/>, an exception will be thrown.</para>
        /// </summary>
        /// <param name="response">An <see cref="WsTrustResponse"/> instance.</param>
        /// <returns>A <see cref="XmlElement"/> instance.</returns>
        public static XmlElement GetRequestedSecurityTokenElement(this WsTrustResponse response)
            => response.GetRequestedSecurityTokenElements().Single();
    }
}
