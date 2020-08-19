using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface IRelyingPartyStore
    {
        ValueTask<IEnumerable<IRelyingParty>> GetRelyingPartiesAsync();
        ValueTask<IRelyingParty> GetRelyingPartyAsync(string appliesTo);
    }
}
