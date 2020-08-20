using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    public class IdentityProviderProvider : IDisposable
    {
        private IDisposable _optionsChangeToken;
        private ILogger<IdentityProviderProvider> _logger;
        private IIdentityProviderStore _store;

        public IdentityProviderProvider(IOptionsMonitor<WsTrustOptions> monitor, ILogger<IdentityProviderProvider> logger, IIdentityProviderStore store = null)
        {
            Options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => Options = options);
            _logger = logger;
            _store = store;
        }
        protected WsTrustOptions Options { get; private set; }

        public async Task<IEnumerable<IIdentityProvider>> GetIdentityProvidersAsync()
        {
            _logger.LogInformation("Getting all identity providers.");
            if (_store == null)
            {
                _logger.LogDebug("No identity provider store configured. Getting in-memory identity providers only.");
                return Options.IdentityProviders.Values;
            }
            var parties = await _store.GetIdentityProvidersAsync();
            return parties.Concat(Options.IdentityProviders.Values);
        }

        public async Task<IIdentityProvider> GetIdentityProviderAsync(string id)
        {
            _logger.LogInformation($"Searching for identity provider: {id}");
            if (_store != null)
            {
                var provider = await _store.GetIdentityProviderAsync(id);
                if (provider != null)
                {
                    _logger.LogInformation($"Found {provider.Name} ({id}) in identity provider store.");
                    return provider;
                }
            }
            if (Options.IdentityProviders.TryGetValue(id, out var idp))
            {
                _logger.LogInformation($"Found {idp.Name} ({id}) in memory.");
                return idp;
            }
            _logger.LogInformation($"Unable to find identity provider: {id}");
            return null;
        }

        public async ValueTask<IIdentityProvider> GetIdentityProviderAsync(SecurityKey key)
        {
            // TODO: find a way to log out information about the security key
            _logger.LogInformation("Searching for identity provider by security key.");
            if (key == null) return null;

            if (_store != null)
            {
                var provider = await _store.GetIdentityProviderAsync(key);
                if (provider != null)
                {
                    _logger.LogInformation($"Found {provider.Name} in identity provider store.");
                    return provider;
                }
            }
            var idp = Options.IdentityProviders.Values.FirstOrDefault(i => i.Enabled && i.SecurityKey?.Equals(key) == true);
            if(idp != null)
                _logger.LogInformation($"Found {idp.Name} in memory.");
            else
                _logger.LogInformation($"Unable to find identity provider by security key.");

            return idp;
        }

        public void Dispose() => _optionsChangeToken?.Dispose();
    }
}
