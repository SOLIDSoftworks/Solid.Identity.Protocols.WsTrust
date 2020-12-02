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
                IssuerSigningKeyValidator = CreateIssuerSigningKeyValidator(_options.Issuer),
                IssuerSigningKeyResolver = CreateIssuerSigningKeyResolver(_options.Issuer),
                TokenDecryptionKeyResolver = ResolveDecryptionKeys,
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

        protected virtual IssuerSigningKeyResolver CreateIssuerSigningKeyResolver(string localIssuer)
        {
            return (token, securityToken, kid, parameters) =>
            {
                _logger.LogInformation($"Finding issuer signing keys for '{securityToken?.Issuer}'.");

                var idp = parameters.GetIdentityProvider(securityToken?.Issuer);
                if (idp == null)
                {
                    _logger.LogWarning($"Issuer '{securityToken?.Issuer}' not found.");
                    return Enumerable.Empty<SecurityKey>();
                }
                if (!idp.Enabled)
                {
                    _logger.LogWarning($"Issuer '{securityToken?.Issuer}' is disabled.");
                    return Enumerable.Empty<SecurityKey>();
                }

                var defaults = new[] { _options.DefaultSigningKey };
                if(idp.ValidEmbeddedCertificateSubjectNames.Any())
                {
                    if (securityToken is SamlSecurityToken saml)
                        defaults = new[] { saml.GetEmbeddedSecurityKey() }.Concat(defaults).ToArray();
                    if (securityToken is Saml2SecurityToken saml2)
                        defaults = new[] { saml2.GetEmbeddedSecurityKey() }.Concat(defaults).ToArray();
                }

                if (idp.Id == localIssuer)
                {
                    _logger.LogInformation($"Issuer is '{idp.Name}' ({idp.Id}). Getting all signing keys.");
                    // TODO: Add a way to see the audience/appliesTo to get the correct signing key
                    return parameters
                        .GetRelyingParties()
                        .Where(rp => rp.Enabled)
                        .Where(rp => rp.SigningKey != null)
                        .Select(rp => rp.SigningKey)
                        .Concat(defaults)
                        .ToArray()
                    ;
                }

                return idp.SecurityKeys.Concat(defaults).Where(k => k != null);
            };
        }
        protected virtual IssuerSigningKeyValidator CreateIssuerSigningKeyValidator(string localIssuer)
        {
            return (key, token, parameters) =>
            {
                if (token?.Issuer == localIssuer) return true;
                _logger.LogInformation($"Validating issuer signing key '{key?.KeyId}' for issuer '{token?.Issuer}'.");

                var idp = parameters.GetIdentityProvider(token?.Issuer);

                if (idp.SecurityKeys.Contains(key))
                {
                    _logger.LogDebug($"Signing key '{key?.KeyId}' is stored in-memory for issuer '{token?.Issuer}'.");
                    return true;
                }
                if (!(key is X509SecurityKey x509))
                {
                    _logger.LogDebug($"Signing key '{key?.KeyId}' is not valid for issuer '{token?.Issuer}'.");
                    return false;
                }

                foreach(var subject in idp.ValidEmbeddedCertificateSubjectNames)
                {
                    if (x509.Certificate.Subject == subject)
                    {
                        _logger.LogDebug($"Embedded signing key '{key?.KeyId}' has a valid subject name ({subject}) for issuer '{token?.Issuer}'.");
                        return true;
                    }
                }
                return false;
            };
        }

        protected virtual IEnumerable<SecurityKey> ResolveDecryptionKeys(string token, SecurityToken securityToken, string kid, TokenValidationParameters parameters)
        {
            _logger.LogDebug("Finding decryption keys.");

            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            var defaults = new[] { _options.DefaultEncryptionKey };
            if (!properties.TryGetValue("rps", out var obj)) return defaults;
            if (!(obj is IDictionary<string, IRelyingParty> rps)) return defaults;

            return rps.Select(rp => rp.Value.EncryptingKey).Where(key => key != null).Concat(defaults);
        }

        protected virtual string ValidateIssuer(string issuer, SecurityToken token, TokenValidationParameters parameters)
        {
            if (!parameters.ValidateIssuer) return issuer;

            _logger.LogDebug($"Validating issuer '{issuer}'.");
            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("idps", out var obj)) throw new SecurityException($"Unable to validate issuer '{issuer}'");

            if (!(obj is IDictionary<string, IIdentityProvider> idps)) throw new SecurityException($"Unable to validate issuer '{issuer}'");

            if (idps.ContainsKey(issuer)) return issuer;
            throw new SecurityException($"Unable to validate issuer '{issuer}'");
        }

        protected virtual bool ValidateAudiences(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters parameters)
        {
            if (!parameters.ValidateAudience) return true;

            _logger.LogDebug($"Validating audience for issuer '{token?.Issuer}'.");
            if (audiences.Contains(_options.Issuer)) return true;
            var request = _httpContextAccessor.HttpContext.Request;
            var url = $"{request.Scheme}://{request.Host}{request.PathBase}{request.Path}{request.QueryString}";
            if (audiences.Contains(url)) return true;

            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("idps", out var obj)) return false;

            if (!(obj is IDictionary<string, IIdentityProvider> idps)) return false;

            if (!idps.TryGetValue(token?.Issuer, out var idp)) return false;

            if (!idp.RestrictRelyingParties) return true;

            var intersect = idp.AllowedRelyingParties.Intersect(audiences);
            return intersect.Any();
        }
    }

    static class TokenValidationParamtersExtensions
    {
        public static IRelyingParty GetRelyingParty(this TokenValidationParameters parameters, string appliesTo)
        {
            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("rps", out var obj)) return null;
            if (!(obj is IDictionary<string, IRelyingParty> rps)) return null;

            if (!rps.TryGetValue(appliesTo, out var rp)) return null;
            return rp;
        }

        public static IEnumerable<IRelyingParty> GetRelyingParties(this TokenValidationParameters parameters)
        {
            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("rps", out var obj)) return Enumerable.Empty<IRelyingParty>();
            if (!(obj is IDictionary<string, IRelyingParty> rps)) return Enumerable.Empty<IRelyingParty>();

            return rps.Values;
        }

        public static IIdentityProvider GetIdentityProvider(this TokenValidationParameters parameters, string issuer)
        {
            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("idps", out var obj)) return null;
            if (!(obj is IDictionary<string, IIdentityProvider> idps)) return null;

            if (!idps.TryGetValue(issuer, out var idp)) return null;
            return idp;
        }

        public static IEnumerable<IIdentityProvider> GetIdentityProviders(this TokenValidationParameters parameters)
        {
            var properties = parameters.PropertyBag ?? new Dictionary<string, object>();
            if (!properties.TryGetValue("idps", out var obj)) return Enumerable.Empty<IIdentityProvider>();
            if (!(obj is IDictionary<string, IIdentityProvider> idps)) return Enumerable.Empty<IIdentityProvider>();

            return idps.Values;
        }
    }
}
