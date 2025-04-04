using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    public class RelyingPartyProvider : IDisposable
    {
        private IDisposable _optionsChangeToken;
        private ILogger<RelyingPartyProvider> _logger;
        private IRelyingPartyStore _store;

        public RelyingPartyProvider(IOptionsMonitor<WsTrustOptions> monitor, ILogger<RelyingPartyProvider> logger, IRelyingPartyStore store = null)
        {
            Options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => Options = options);
            _logger = logger;
            _store = store;
        }
        protected WsTrustOptions Options { get; private set; }

        public async Task<IEnumerable<IRelyingParty>> GetRelyingPartiesAsync()
        {
            using var activity = Tracing.WsTrust.Base.StartActivity($"{nameof(RelyingPartyProvider)}.{nameof(GetRelyingPartiesAsync)}");
            _logger.LogInformation("Getting all relying parties.");
            if (_store == null)
            {
                _logger.LogDebug("No relying party store configured. Getting in-memory relying parties only.");
                return Options.RelyingParties.Values;
            }
            var parties = await _store.GetRelyingPartiesAsync();
            return parties.Concat(Options.RelyingParties.Values);
        }

        public async Task<IRelyingParty> GetRelyingPartyAsync(string appliesTo)
        {
            using var activity = Tracing.WsTrust.Base.StartActivity($"{nameof(RelyingPartyProvider)}.{nameof(GetRelyingPartyAsync)}");
            _logger.LogInformation($"Searching for relying party: {appliesTo}");
            if(_store != null)
            {
                var party = await _store.GetRelyingPartyAsync(appliesTo);
                if(party != null)
                {
                    _logger.LogInformation($"Found {party.Name} ({appliesTo}) in relying party store.");
                    return party;
                }
            }
            if (Options.RelyingParties.TryGetValue(appliesTo, out var rp))
            {
                _logger.LogInformation($"Found {rp.Name} ({appliesTo}) in memory.");
                return rp;
            }
            _logger.LogInformation($"Unable to find relying party: {appliesTo}");
            return null;
        }
        public void Dispose() => _optionsChangeToken?.Dispose();
    }
}
