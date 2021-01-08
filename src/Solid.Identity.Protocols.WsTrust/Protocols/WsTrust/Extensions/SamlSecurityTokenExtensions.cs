using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    internal static class SamlSecurityTokenExtensions
    {
        public static IEnumerable<SecurityKey> GetEmbeddedSecurityKeys(this SamlSecurityToken saml)
        {
            if (saml?.Assertion?.Signature?.KeyInfo == null) Enumerable.Empty<SecurityKey>();
            return saml.Assertion.Signature.KeyInfo.GetSecurityKeys();
        }
    }
}
