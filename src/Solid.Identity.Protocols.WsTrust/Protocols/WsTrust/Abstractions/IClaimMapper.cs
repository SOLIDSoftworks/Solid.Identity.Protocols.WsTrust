using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface IClaimMapper
    {
        string IncomingClaimIssuer { get; }
        ValueTask<IEnumerable<Claim>> MapClaimsAsync(IEnumerable<Claim> claim);
    }
}
