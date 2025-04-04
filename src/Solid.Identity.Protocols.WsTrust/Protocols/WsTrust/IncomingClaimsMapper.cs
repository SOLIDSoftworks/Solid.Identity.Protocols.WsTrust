using Microsoft.Extensions.Logging;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    public class IncomingClaimsMapper
    {
        private readonly Dictionary<string, IEnumerable<IClaimMapper>> _mappers;
        private readonly ILogger<IncomingClaimsMapper> _logger;

        public IncomingClaimsMapper(IEnumerable<IClaimMapper> mappers, ILogger<IncomingClaimsMapper> logger)
        {
            _mappers = mappers
                .GroupBy(m => m.IncomingClaimIssuer ?? "*")
                .ToDictionary(g => g.Key, g => g.AsEnumerable())
            ;
            _logger = logger;
        }

        public async ValueTask<IEnumerable<Claim>> MapIncomingClaimsAsync(IEnumerable<Claim> claims)
        {
            using var activity = Tracing.WsTrust.Base.StartActivity($"{nameof(IncomingClaimsMapper)}.{nameof(MapIncomingClaimsAsync)}");
            var mapped = new List<Claim>();

            if (_mappers.TryGetValue("*", out var global))
            {
                foreach (var mapper in global)
                    mapped.AddRange(await mapper.MapClaimsAsync(claims));
            }

            var groups = mapped.Concat(claims).ToArray()
                .GroupBy(c => c.Issuer)// TODO: OriginalIssuer?
            ;

            foreach (var group in groups)
            {
                if (!_mappers.TryGetValue(group.Key, out var mappers))
                {
                    _logger.LogDebug($"Unable to find mapper for claims from '{group.Key}'. Allowing pass-through.");
                    mapped.AddRange(group.AsEnumerable());
                    continue;
                }
                _logger.LogDebug($"Mapping claims from '{group.Key}'.");
                foreach (var mapper in mappers)
                    mapped.AddRange(await mapper.MapClaimsAsync(group));
            }

            return mapped;
        }
    }
}
