using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public abstract class ClaimStore : IRelyingPartyClaimStore
    {
        public virtual bool CanGenerateClaims(string appliesTo) => true;

        public abstract IEnumerable<ClaimDescriptor> ClaimTypesOffered { get; }

        public abstract ValueTask<IEnumerable<Claim>> GetClaimsAsync(ClaimsIdentity identity, IRelyingParty party);
    }
}
