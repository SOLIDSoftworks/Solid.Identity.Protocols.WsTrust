using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    internal class WsTrustTokenValidationParametersFactory : ITokenValidationParametersFactory
    {
        private WsTrustOptions _options;
        private readonly IDisposable _optionsChangeToken;
        private readonly IIdentityProviderStore _identityProviders;
        private readonly IRelyingPartyStore _relyingParties;
        private readonly ILogger<WsTrustTokenValidationParametersFactory> _logger;

        public WsTrustTokenValidationParametersFactory(
            IIdentityProviderStore identityProviders,
            IRelyingPartyStore relyingParties,
            ILogger<WsTrustTokenValidationParametersFactory> logger,
            IOptionsMonitor<WsTrustOptions> monitor)
        {
            _identityProviders = identityProviders;
            _relyingParties = relyingParties;
            _logger = logger;
            _options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => _options = options);
        }

        public async ValueTask<TokenValidationParameters> CreateAsync()
        {
            var idps = (await _identityProviders.GetIdentityProvidersAsync())
                .Where(idp => idp.Enabled)
                .ToDictionary(idp => idp.Id, idp => idp)
            ;
            var rps = (await _relyingParties.GetRelyingPartiesAsync())
                .Where(rp => rp.Enabled)
                .ToDictionary(rp => rp.Id, rp => rp)
            ;

            var parameters = new TokenValidationParameters
            {
                ValidAudiences = rps.Keys,
                ValidIssuers = idps.Keys,
                ValidateAudience = true,
                ValidateIssuer = true,

                ClockSkew = _options.MaxClockSkew,
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                {
                    _logger.LogDebug($"Finding issuer signing key for '{securityToken?.Issuer}'.");
                    if (!idps.TryGetValue(securityToken?.Issuer, out var idp)) return null;
                    return new[] { idp.SecurityKey };
                }
            };
            parameters.ValidateAudience = true;
            parameters.ValidateIssuer = true;

            parameters.IssuerValidator = (issuer, token, _) =>
            {
                _logger.LogDebug($"Validating issuer '{issuer}'.");
                if (idps.ContainsKey(issuer)) return issuer;
                throw new SecurityException($"Unable to validate issuer '{issuer}'");
            };

            parameters.AudienceValidator = (audiences, token, _) =>
            {
                if (!idps.TryGetValue(token?.Issuer, out var idp)) return false;

                if (!idp.RestrictRelyingParties) return true;

                _logger.LogDebug($"Validating audience for issuer '{token?.Issuer}'.");
                var intersect = idp.AllowedRelyingParties.Select(p => p.AbsoluteUri).Intersect(audiences);
                return intersect.Any();
            };

            return parameters;
        }
        //private IEnumerable<SecurityKey> GetIncludedSecurityKeys(Signature signature)
        //{
        //    if (signature?.KeyInfo == null) return null;
        //    return signature
        //        .KeyInfo
        //        .X509Data
        //        .SelectMany(data => data.Certificates)
        //        .Select(base64 => Convert.FromBase64String(base64))
        //        .Select(raw => new X509Certificate2(raw))
        //        .Select(cert => new X509SecurityKey(cert))
        //        .ToArray()
        //    ;
        //}
    }
}
