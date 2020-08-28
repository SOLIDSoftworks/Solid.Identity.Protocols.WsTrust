using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    internal class SamlClaimStore : ITokenTypeClaimStore
    {
        public bool CanGenerateClaims(string tokenType) => 
            tokenType == SamlConstants.Saml11Namespace ||
            tokenType == Saml2Constants.Saml2TokenProfile11 || tokenType == Saml2Constants.OasisWssSaml2TokenProfile11;

        public ValueTask<IEnumerable<Claim>> GetClaimsAsync(ClaimsIdentity identity, IRelyingParty party, IEnumerable<Claim> outgoingClaims)
        {
            var attributes = outgoingClaims
                .Where(c => c.Type != ClaimTypes.NameIdentifier)
                .Where(c => c.Type != ClaimTypes.AuthenticationInstant)
                .Where(c => c.Type != ClaimTypes.AuthenticationMethod)
            ;
            var claims = new List<Claim>();
            if (!attributes.Any())
                claims.Add(new Claim("http://schemas.solidsoft.works/ws/2020/08/identity/claims/null", bool.TrueString, ClaimValueTypes.Boolean));

            return new ValueTask<IEnumerable<Claim>>(claims);
        }
    }
}
