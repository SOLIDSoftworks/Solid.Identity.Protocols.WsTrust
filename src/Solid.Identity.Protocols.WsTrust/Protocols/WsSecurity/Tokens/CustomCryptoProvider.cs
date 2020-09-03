using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
                _logger.LogDebug($"Creating {nameof(HashAlgorithm)} for '{algorithm}'");
                return hashAlgorithmDescriptor.Factory(_services, args);
            }
            if (_options.SupportedSignatureAlgorithms.TryGetValue(algorithm, out var signatureProviderDescriptor))
            {
                _logger.LogDebug($"Creating {nameof(SignatureProvider)} for '{algorithm}'");
                return signatureProviderDescriptor.Factory(_services, args);
            }
            if (_options.SupportedKeyedHashAlgorithms.TryGetValue(algorithm, out var keyedHashAlgorithmDescriptor))
            {
                _logger.LogDebug($"Creating {nameof(KeyedHashAlgorithm)} for '{algorithm}'");
                return keyedHashAlgorithmDescriptor.Factory(_services, args);
            }
            if (_options.SupportedEncryptionAlgorithms.TryGetValue(algorithm, out var authenticatedEncryptionProviderDescriptor))
            {
                _logger.LogDebug($"Creating {nameof(AuthenticatedEncryptionProvider)} for '{algorithm}'");
                return authenticatedEncryptionProviderDescriptor.Factory(_services, args);
            }
            if (_options.SupportedKeyWrapAlgorithms.TryGetValue(algorithm, out var keyWrapProviderDescriptor))
            {
                _logger.LogDebug($"Creating {nameof(KeyWrapProvider)} for '{algorithm}'");
                return keyWrapProviderDescriptor.Factory(_services, args);
            }

            throw new NotSupportedException(algorithm);
        }

        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        {
            return 
                _options.SupportedHashAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedSignatureAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedEncryptionAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedKeyedHashAlgorithms.ContainsKey(algorithm) ||
                _options.SupportedKeyWrapAlgorithms.ContainsKey(algorithm)
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
