using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface IRelyingPartyClaimStore
    {
        bool CanGenerateClaims(string appliesTo);
        IEnumerable<ClaimDescriptor> ClaimTypesOffered { get; }
        ValueTask<IEnumerable<Claim>> GetClaimsAsync(ClaimsIdentity identity, IRelyingParty party);
    }
}
