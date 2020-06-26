using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Defaults
{
    public class DefaultIdentityProviderStore : IIdentityProviderStore, IDisposable
    {
        private IDisposable _optionsChangeToken;

        public DefaultIdentityProviderStore(IOptionsMonitor<WsTrustOptions> monitor)
        {
            Options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => Options = options);
        }
        protected WsTrustOptions Options { get; private set; }

        public ValueTask<IIdentityProvider> GetIdentityProviderAsync(string id)
        {
            if (Options.IdentityProviders.TryGetValue(id, out var idp)) return new ValueTask<IIdentityProvider>(idp);
            return new ValueTask<IIdentityProvider>();
        }

        public ValueTask<IIdentityProvider> GetIdentityProviderAsync(SecurityKey key)
        {
            if (key == null) return new ValueTask<IIdentityProvider>();
            var idp = Options.IdentityProviders.Values.FirstOrDefault(i => i.Enabled && i.SecurityKey?.Equals(key) == true);
            return new ValueTask<IIdentityProvider>(idp);
        }

        public ValueTask<IEnumerable<IIdentityProvider>> GetIdentityProvidersAsync() => new ValueTask<IEnumerable<IIdentityProvider>>(Options.IdentityProviders.Values);

        public void Dispose() => _optionsChangeToken?.Dispose();
    }
}
