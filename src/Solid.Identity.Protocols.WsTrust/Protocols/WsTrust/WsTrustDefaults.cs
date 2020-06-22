using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;
using Solid.Identity.Protocols.WsSecurity.Tokens;

namespace Solid.Identity.Protocols.WsTrust
{
    public static class WsTrustDefaults
    {
        public static readonly string DefaultTokenType = Saml2Constants.Saml2TokenProfile11;
        public static readonly int DefaultSymmetricKeySizeInBits = 256;
        public static readonly int DefaultMaxSymmetricKeySizeInBits = 1024;
        public static readonly TimeSpan DefaultTokenLifetime = TimeSpan.FromHours(1);
        public static readonly TimeSpan MaxTokenLifetime = TimeSpan.FromHours(2);
        public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);

        internal static List<SecurityTokenHandlerDescriptor> SecurityTokenHandlers => new List<SecurityTokenHandlerDescriptor>
        {
            new SecurityTokenHandlerDescriptor(Enumerable.Empty<string>(), p => p.GetService<UserNameSecurityTokenHandler>()),
            new SecurityTokenHandlerDescriptor(Enumerable.Empty<string>(), p => p.GetService<X509Certificate2SecurityTokenHandler>())
        };
    }
}
