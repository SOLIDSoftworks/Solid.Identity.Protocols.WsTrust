using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class CustomCryptoProvider : ICryptoProvider, IDisposable
    {
        private readonly ILogger<CustomCryptoProvider> _logger;
        private readonly IServiceProvider _services;
        private WsTrustOptions _options;
        private readonly IDisposable _optionsChangeToken;

        public CustomCryptoProvider(IOptionsMonitor<WsTrustOptions> monitor, ILogger<CustomCryptoProvider> logger, IServiceProvider services)
        {
            _options = monitor.CurrentValue;
            _optionsChangeToken = monitor.OnChange((options, _) => _options = options);

            _logger = logger;
            _services = services;
        }

        public object Create(string algorithm, params object[] args)
        {
            if (_options.SupportedHashAlgorithms.TryGetValue(algorithm, out var hashAlgorithmDescriptor))
            {
                _logger.LogDebug($"Creating hash algorithm for '{algorithm}'");
                return hashAlgorithmDescriptor.Factory(_services, args);
            }
            if (_options.SupportedSignatureAlgorithms.TryGetValue(algorithm, out var signatureProviderDescriptor))
            {
                _logger.LogDebug($"Creating signature provider for '{algorithm}'");
                return signatureProviderDescriptor.Factory(_services, args);
            }

            throw new NotSupportedException(algorithm);
        }

        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        {
            return 
                _options.SupportedHashAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedSignatureAlgorithms.ContainsKey(algorithm)
            ;
        }

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposable)
                disposable?.Dispose();
        }

        public void Dispose() => _optionsChangeToken?.Dispose();
    }
}
