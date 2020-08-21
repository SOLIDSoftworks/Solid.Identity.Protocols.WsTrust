using Microsoft.AspNetCore.Http;
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
        private readonly IdentityProviderProvider _identityProviders;
        private readonly RelyingPartyProvider _relyingParties;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<WsTrustTokenValidationParametersFactory> _logger;

        public WsTrustTokenValidationParametersFactory(
            IdentityProviderProvider identityProviders,
            RelyingPartyProvider relyingParties,
            IHttpContextAccessor httpContextAccessor,
            ILogger<WsTrustTokenValidationParametersFactory> logger,
            IOptionsMonitor<WsTrustOptions> monitor)
        {
            _identityProviders = identityProviders;
            _relyingParties = relyingParties;
            _httpContextAccessor = httpContextAccessor;
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
                IssuerSigningKeyResolver = ResolveIssuerSigningKeys,
                IssuerValidator = ValidateIssuer,
                AudienceValidator = ValidateAudiences
            };

            parameters.PropertyBag = new Dictionary<string, object>
            {
                { "idps", idps },
                { "rps", rps }
            };

            return parameters;
        }

        protected virtual IEnumerable<SecurityKey> ResolveIssuerSigningKeys(string token, SecurityToken securityToken, string kid, TokenValidationParameters parameters)
        {
            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("idps", out var obj)) return Enumerable.Empty<SecurityKey>();
            if (!(obj is IDictionary<string, IIdentityProvider> idps)) return Enumerable.Empty<SecurityKey>();

            _logger.LogDebug($"Finding issuer signing key for '{securityToken?.Issuer}'.");
            if (!idps.TryGetValue(securityToken?.Issuer, out var idp)) return null;
            return new[] { idp.SecurityKey };
        }

        protected virtual string ValidateIssuer(string issuer, SecurityToken token, TokenValidationParameters parameters)
        {
            if (!parameters.ValidateIssuer) return issuer;

            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("idps", out var obj)) throw new SecurityException($"Unable to validate issuer '{issuer}'");

            if (!(obj is IDictionary<string, IIdentityProvider> idps)) throw new SecurityException($"Unable to validate issuer '{issuer}'");

            _logger.LogDebug($"Validating issuer '{issuer}'.");
            if (idps.ContainsKey(issuer)) return issuer;
            throw new SecurityException($"Unable to validate issuer '{issuer}'");
        }

        protected virtual bool ValidateAudiences(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters parameters)
        {
            if (!parameters.ValidateAudience) return true;

            if (audiences.Contains(_options.Issuer)) return true;
            var request = _httpContextAccessor.HttpContext.Request;
            var url = $"{request.Scheme}://{request.Host}{request.PathBase}{request.Path}{request.QueryString}";
            if (audiences.Contains(url)) return true;

            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("idps", out var obj)) return false;

            if (!(obj is IDictionary<string, IIdentityProvider> idps)) return false;

            if (!idps.TryGetValue(token?.Issuer, out var idp)) return false;

            if (!idp.RestrictRelyingParties) return true;

            _logger.LogDebug($"Validating audience for issuer '{token?.Issuer}'.");
            var intersect = idp.AllowedRelyingParties.Intersect(audiences);
            return intersect.Any();
        }
    }
}
