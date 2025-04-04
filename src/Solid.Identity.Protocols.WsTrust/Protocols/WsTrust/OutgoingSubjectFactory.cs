using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Solid.Identity.Protocols.WsTrust.Logging;
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
            using var activity = Tracing.WsTrust.Base.StartActivity($"{nameof(OutgoingSubjectFactory)}.{nameof(CreateOutgoingSubjectAsync)}");
            var claims = new List<Claim>();

            var required = relyingParty.RequiredClaims ?? Enumerable.Empty<string>();
            var optional = relyingParty.OptionalClaims ?? Enumerable.Empty<string>();

            _logger.LogInformation($"Getting required claims for party: {relyingParty.AppliesTo}");
            if (required.Any())
            {
                if (!await TryGetClaimsAsync(required, nameof(required), identity, relyingParty, claims))
                    throw new SecurityException($"Unable to get all required claim values for party: {relyingParty.AppliesTo}");
            }
            else
            {
                _logger.LogInformation($"No required claims for party: {relyingParty.AppliesTo}");
            }

            _logger.LogInformation($"Getting optional claims for party: {relyingParty.AppliesTo}");
            if(optional.Any())
                _ = await TryGetClaimsAsync(optional, nameof(optional), identity, relyingParty, claims);
            else
                _logger.LogInformation($"No optional claims for party: {relyingParty.AppliesTo}");


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

            var outgoing = new ClaimsIdentity(claims, identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
            return outgoing;
        }

        private async Task<bool> TryGetClaimsAsync(IEnumerable<string> requestedClaimTypes, string requirement, ClaimsIdentity source, IRelyingParty party, ICollection<Claim> claims)
        {
            var list = requestedClaimTypes.ToList();
            var stores = new List<IRelyingPartyClaimStore>();

            foreach(var type in requestedClaimTypes)
            {
                if (!_relyingPartyClaimStores.TryGetValue(type, out var relyingPartyClaimStores))
                    continue;
                stores.AddRange(relyingPartyClaimStores);
            }

            foreach (var store in stores.Distinct())
            {
                if (!store.CanGenerateClaims(party.AppliesTo)) continue;

                _logger.LogDebug($"Attempting to get {requirement} claims from {store.GetType().Name}");
                var requiredClaims = await store.GetClaimsAsync(source, party);
                foreach (var claim in requiredClaims)
                {
                    _logger.LogTrace($"Adding {requirement} claim '{claim.Type}' from {store.GetType().Name}");
                    claims.Add(claim);
                    if (list.Contains(claim.Type))
                        list.Remove(claim.Type);
                }
            }

            var copy = list.ToArray();
            foreach(var type in copy)
            {
                var claim = source.FindFirst(type);
                if (claim == null) continue;

                _logger.LogDebug($"Adding {requirement} claim '{type}' from source identity.");
                claims.Add(claim);
                list.Remove(type);
            }

            var success = !list.Any();
            if (!success)
                WsTrustLogMessages.UnableToGetAllClaims(_logger, requirement, new UnableToGetAllClaims { UnpopulatedClaimTypes = list }, null);

            return success;
        }
    }
}
