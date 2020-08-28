using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface ITokenTypeClaimStore
    {
        bool CanGenerateClaims(string tokenType);
        ValueTask<IEnumerable<Claim>> GetClaimsAsync(ClaimsIdentity identity, IRelyingParty party, IEnumerable<Claim> outgoingClaims);
    }
}
