using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Solid.Identity.Protocols.WsTrust.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Defaults
{
    public class DefaultSecurityTokenService : SecurityTokenService
    {
        private readonly IRelyingPartyStore _relyingParties;

        public DefaultSecurityTokenService(IRelyingPartyStore relyingParties, SecurityTokenHandlerProvider securityTokenHandlerProvider, IOptions<WsTrustOptions> options, ISystemClock systemClock) 
            : base(securityTokenHandlerProvider, options, systemClock)
        {
            _relyingParties = relyingParties;
        }

        protected override ValueTask<ClaimsIdentity> CreateOutgoingSubjectAsync(ClaimsPrincipal principal, WsTrustRequest request, Scope scope, CancellationToken cancellationToken)
        {
            return new ValueTask<ClaimsIdentity>(principal.Identities.First());
        }

        protected override async ValueTask<Scope> GetScopeAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken)
        {
            if(request.AppliesTo == null)
            {
                if (Options.DefaultAppliesTo == null)
                    throw new InvalidRequestException("AppliesTo not specified");
                request.AppliesTo = new AppliesTo(new EndpointReference(Options.DefaultAppliesTo.ToString()));
            }
            var appliesTo = request.AppliesTo.EndpointReference.Uri;
            var party = await _relyingParties.GetRelyingPartyAsync(appliesTo);
            var scope = new Scope(appliesTo, party.SigningKey, party.SigningAlgorithm, party.EncryptingKey, party.EncryptingAlgorithm);
            return scope;
        }
    }
}
