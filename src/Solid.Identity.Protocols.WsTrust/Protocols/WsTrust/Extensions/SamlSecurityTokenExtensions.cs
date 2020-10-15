using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    internal static class SamlSecurityTokenExtensions
    {
        public static SecurityKey GetEmbeddedSecurityKey(this SamlSecurityToken saml) => saml?.Assertion?.SigningCredentials?.Key;
    }
}
