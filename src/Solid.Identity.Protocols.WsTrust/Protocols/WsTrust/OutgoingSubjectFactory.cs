using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    public class OutgoingSubjectFactory
    {
        private IDictionary<string, IEnumerable<IRelyingPartyClaimStore>> _relyingPartyClaimStores;
        private IEnumerable<ITokenTypeClaimStore> _tokenTypeClaimStores;
        private ILogger<OutgoingSubjectFactory> _logger;

        public OutgoingSubjectFactory(IEnumerable<IRelyingPartyClaimStore> relyingPartyClaimStores, IEnumerable<ITokenTypeClaimStore> tokenTypeClaimStores, ILogger<OutgoingSubjectFactory> logger)
        {
            _relyingPartyClaimStores = relyingPartyClaimStores
                .SelectMany(s => s.ClaimTypesOffered.Select(t => new KeyValuePair<string, IRelyingPartyClaimStore>(t.Type, s)))
                .GroupBy(p => p.Key, p => p.Value)
                .ToDictionary(g => g.Key, g => g.AsEnumerable())
            ;

            _tokenTypeClaimStores = tokenTypeClaimStores;

            _logger = logger;
        }

        public async ValueTask<ClaimsIdentity> CreateOutgoingSubjectAsync(ClaimsIdentity identity, IRelyingParty relyingParty, string tokenType)
        {
            var claims = new List<Claim>();

            foreach (var required in relyingParty.RequiredClaims ?? Enumerable.Empty<string>())
            {
                var c = identity.FindFirst(required);
                if(c != null)
                {
                    claims.Add(c);
                    continue;
                }

                _logger.LogDebug($"Getting required claim: {required}");

                if (!_relyingPartyClaimStores.TryGetValue(required, out var relyingPartyClaimStores))
                    throw new SecurityException($"Unable to create claim value for required claim: {required}");
                foreach (var store in relyingPartyClaimStores)
                {
                    if (!store.CanGenerateClaims(relyingParty.AppliesTo)) continue;

                    var requiredClaims = await store.GetClaimsAsync(identity, relyingParty);
                    foreach (var claim in requiredClaims)
                    {
                        _logger.LogTrace($"Adding {claim.Type} from {store.GetType().Name}");
                        claims.Add(claim);
                    }

                    claims.AddRange(await store.GetClaimsAsync(identity, relyingParty));
                }
            }

            foreach (var optional in relyingParty.OptionalClaims ?? Enumerable.Empty<string>())
            {

                var c = identity.FindFirst(optional);
                if (c != null)
                {
                    claims.Add(c);
                    continue;
                }

                _logger.LogDebug($"Attempting to get optional claim: {optional}");

                if (!_relyingPartyClaimStores.TryGetValue(optional, out var relyingPartyClaimStores))
                {
                    _logger.LogDebug($"Unable to get claim value for optional claim: {optional} - Skipping...");
                    continue;
                }

                foreach (var store in relyingPartyClaimStores)
                {
                    if (!store.CanGenerateClaims(relyingParty.AppliesTo)) continue;

                    var requiredClaims = await store.GetClaimsAsync(identity, relyingParty);
                    foreach (var claim in requiredClaims)
                    {
                        _logger.LogTrace($"Adding {claim.Type} from {store.GetType().Name}");
                        claims.Add(claim);
                    }
                }
            }

            var tokenTypeClaimStores = _tokenTypeClaimStores.Where(s => s.CanGenerateClaims(tokenType));
            if (tokenTypeClaimStores.Any())
            {
                _logger.LogDebug($"Getting claims for token type: {tokenType}");
                foreach (var store in tokenTypeClaimStores)
                {
                    var tokenTypeClaims = await store.GetClaimsAsync(identity, relyingParty, claims);
                    foreach (var claim in tokenTypeClaims)
                    {
                        _logger.LogTrace($"Adding {claim.Type} from {store.GetType().Name}");
                        claims.Add(claim);
                    }
                }
            }

            //AddRequiredClaims(claims, identity.NameClaimType, identity.RoleClaimType);

            var outgoing = new ClaimsIdentity(claims, identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
            return outgoing;
        }

        private void AddRequiredClaims(List<Claim> claims, string nameClaimType, string roleClaimType)
        {
            if (!claims.Any())
            {
                _logger.LogDebug("No user claims created. Adding null claim for SAML attribute statements.");
                // TODO: Should we add this claim when the claim collection is empty?
                // Right now, this is done so the SAML2 attribute statement won't be empty.
                claims.Add(new Claim("http://schemas.solidsoft.works/ws/2020/08/identity/claims/null", bool.TrueString, ClaimValueTypes.Boolean));
            }

            var name = claims.FirstOrDefault(c => c.Type == nameClaimType)?.Value;
            if (name != null && !claims.Any(c => c.Type == ClaimTypes.NameIdentifier))
            {
                _logger.LogDebug($"Adding claim: {ClaimTypes.NameIdentifier}");
                claims.Add(new Claim(ClaimTypes.NameIdentifier, name, ClaimValueTypes.String));
            }
            if (!claims.Any(c => c.Type == ClaimTypes.AuthenticationInstant))
            {
                var now = AuthenticationInstantClaim.Now;
                _logger.LogDebug($"Adding claim: {now.Type}");
                claims.Add(AuthenticationInstantClaim.Now);
            }
            if (!claims.Any(c => c.Type == ClaimTypes.AuthenticationMethod))
            {
                _logger.LogDebug($"Adding claim: {ClaimTypes.AuthenticationMethod}");
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/unspecified", ClaimValueTypes.String));
            }
        }
    }
}
