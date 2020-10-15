using System;
using System.Collections.Generic;
using System.Text;


namespace Microsoft.IdentityModel.Tokens.Saml2
{
    internal static class Saml2SecurityTokenExtensions
    {
        public static SecurityKey GetEmbeddedSecurityKey(this Saml2SecurityToken saml) => saml?.Assertion?.SigningCredentials?.Key;
    }
}

