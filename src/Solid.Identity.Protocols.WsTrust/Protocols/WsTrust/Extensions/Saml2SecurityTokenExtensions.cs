using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace Microsoft.IdentityModel.Tokens.Saml2
{
    internal static class Saml2SecurityTokenExtensions
    {
        public static IEnumerable<SecurityKey> GetEmbeddedSecurityKeys(this Saml2SecurityToken saml)
        {
            if (saml?.Assertion?.Signature?.KeyInfo == null) Enumerable.Empty<SecurityKey>();
            return saml.Assertion.Signature.KeyInfo.GetSecurityKeys();
        }
    }
}

