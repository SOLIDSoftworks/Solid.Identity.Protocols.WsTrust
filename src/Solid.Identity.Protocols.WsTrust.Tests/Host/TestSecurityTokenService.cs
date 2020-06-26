using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Tests.Host
{
    class TestSecurityTokenService : SecurityTokenService
    {
        public TestSecurityTokenService(SecurityTokenHandlerProvider securityTokenHandlerProvider, IOptions<WsTrustOptions> options, ISystemClock systemClock) 
            : base(securityTokenHandlerProvider, options, systemClock)
        {
        }

        protected override ValueTask<ClaimsIdentity> CreateOutgoingSubjectAsync(ClaimsPrincipal principal, WsTrustRequest request, Scope scope, CancellationToken cancellationToken)
        {
            var incoming = principal.Identity as ClaimsIdentity;
            var claims = new[]
            { 
                incoming.FindFirst(ClaimTypes.NameIdentifier),
                new Claim("uri://identity/type", "test")
            };

            var identity = new ClaimsIdentity(claims);
            return new ValueTask<ClaimsIdentity>(identity);
        }

        protected override ValueTask<Scope> GetScopeAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken)
            => new ValueTask<Scope>(new Scope(request.AppliesTo.EndpointReference.Uri.AbsoluteUri));
    }
}
