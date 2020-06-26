using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface IIdentityProviderStore
    {
        ValueTask<IEnumerable<IIdentityProvider>> GetIdentityProvidersAsync();
        ValueTask<IIdentityProvider> GetIdentityProviderAsync(string id);
        ValueTask<IIdentityProvider> GetIdentityProviderAsync(SecurityKey key);
    }
}
