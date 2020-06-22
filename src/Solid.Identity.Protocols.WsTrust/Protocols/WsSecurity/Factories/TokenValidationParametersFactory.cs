using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Solid.Identity.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Factories
{
    internal class TokenValidationParametersFactory : IDisposable
    {
        private WsTrustOptions _options;
        private IDisposable _optionsChangeToken;

        public TokenValidationParametersFactory(IOptionsMonitor<WsTrustOptions> monitor)
        {
            _options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => _options = options);
        }
        public TokenValidationParameters Create()
            => new TokenValidationParameters
            {
                ClockSkew = _options.MaxClockSkew,
                //LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
                //{

                //},
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                {
                    if (securityToken is SamlSecurityToken saml)
                        return GetIncludedSecurityKeys(saml.Assertion.Signature);
                    if (securityToken is Saml2SecurityToken saml2)
                        return GetIncludedSecurityKeys(saml2.Assertion.Signature);

                    // maybe add some options for more of these resolver methods

                    return null;
                },
                ValidateActor = false,
                ValidateAudience = false,
                ValidateIssuer = false
            };

        public void Dispose() => _optionsChangeToken?.Dispose();

        private IEnumerable<SecurityKey> GetIncludedSecurityKeys(Signature signature)
        {
            if (signature?.KeyInfo == null) return null;
            return signature
                .KeyInfo
                .X509Data
                .SelectMany(data => data.Certificates)
                .Select(base64 => Convert.FromBase64String(base64))
                .Select(raw => new X509Certificate2(raw))
                .Select(cert => new X509SecurityKey(cert))
                .ToArray()
            ;
        }
    }
}
