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
            : this(monitor.CurrentValue, services)
        {
            _optionsChangeToken = monitor.OnChange((options, _) => _options = options);

            _logger = logger;
        }

        // for testing
        internal CustomCryptoProvider(WsTrustOptions options, IServiceProvider services)
        {
            _options = options;
            _services = services;
        }

        public object Create(string algorithm, params object[] args)
        {
            if (_options.SupportedHashAlgorithms.TryGetValue(algorithm, out var hashAlgorithmDescriptor) && CanCreateCryptoWithArgs<HashAlgorithm>(args))
            {
                _logger?.LogDebug($"Creating {nameof(HashAlgorithm)} for '{algorithm}'");
                return hashAlgorithmDescriptor.Factory(_services, args);
            }
            if (_options.SupportedSignatureAlgorithms.TryGetValue(algorithm, out var signatureProviderDescriptor) && CanCreateCryptoWithArgs<SignatureProvider>(args))
            {
                _logger?.LogDebug($"Creating {nameof(SignatureProvider)} for '{algorithm}'");
                return signatureProviderDescriptor.Factory(_services, args);
            }
            if (_options.SupportedKeyedHashAlgorithms.TryGetValue(algorithm, out var keyedHashAlgorithmDescriptor) && CanCreateCryptoWithArgs<KeyedHashAlgorithm>(args))
            {
                _logger?.LogDebug($"Creating {nameof(KeyedHashAlgorithm)} for '{algorithm}'");
                return keyedHashAlgorithmDescriptor.Factory(_services, args);
            }
            if (_options.SupportedEncryptionAlgorithms.TryGetValue(algorithm, out var authenticatedEncryptionProviderDescriptor) && CanCreateCryptoWithArgs<AuthenticatedEncryptionProvider>(args))
            {
                _logger?.LogDebug($"Creating {nameof(AuthenticatedEncryptionProvider)} for '{algorithm}'");
                return authenticatedEncryptionProviderDescriptor.Factory(_services, args);
            }
            if (_options.SupportedKeyWrapAlgorithms.TryGetValue(algorithm, out var keyWrapProviderDescriptor) && CanCreateCryptoWithArgs<KeyWrapProvider>(args))
            {
                _logger?.LogDebug($"Creating {nameof(KeyWrapProvider)} for '{algorithm}'");
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

        private bool CanCreateCryptoWithArgs<T>(object[] args)
        {
            if (typeof(T) == typeof(HashAlgorithm) && args.Length == 0) return true;
            if (typeof(T) == typeof(SignatureProvider) && args.Length == 2 && args[0] is SecurityKey && args[1] is bool) return true;
            if (typeof(T) == typeof(KeyedHashAlgorithm) && args.Length == 1 && args[0] is byte[]) return true;
            if (typeof(T) == typeof(AuthenticatedEncryptionProvider) && args.Length == 1 && args[0] is SecurityKey) return true;
            if (typeof(T) == typeof(KeyWrapProvider) && args.Length == 2 && args[0] is SecurityKey && args[1] is bool) return true;

            return false;
        }
    }
}
