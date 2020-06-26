using Microsoft.Extensions.Options;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Defaults
{
    public class DefaultRelyingPartyStore : IRelyingPartyStore, IDisposable
    {
        private IDisposable _optionsChangeToken;

        public DefaultRelyingPartyStore(IOptionsMonitor<WsTrustOptions> monitor)
        {
            Options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => Options = options);
        }
        protected WsTrustOptions Options { get; private set; }

        public ValueTask<IEnumerable<IRelyingParty>> GetRelyingPartiesAsync() => new ValueTask<IEnumerable<IRelyingParty>>(Options.RelyingParties.Values);

        public ValueTask<IRelyingParty> GetRelyingPartyAsync(Uri appliesTo)
        {
            if (Options.RelyingParties.TryGetValue(appliesTo, out var rp)) return new ValueTask<IRelyingParty>(rp);
            return new ValueTask<IRelyingParty>();
        }
        public void Dispose() => _optionsChangeToken?.Dispose();
    }
}
