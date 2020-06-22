using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsTrust;
using Solid.Identity.Tokens;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    public class SecurityTokenHandlerProvider : IDisposable
    {
        private IDisposable _optionsChangeToken;
        private IReadOnlyDictionary<Type, SecurityTokenHandler> _handlersByType;
        private IReadOnlyDictionary<string, SecurityTokenHandler> _handlersByTokenTypeIdentifier;
        private IServiceProvider _services;

        public SecurityTokenHandlerProvider(IServiceProvider services, IOptionsMonitor<WsTrustOptions> monitor)
        {
            _services = services;
            _optionsChangeToken = monitor.OnChange((options, _) => UpdateSecurityTokenHandlers(options));
            UpdateSecurityTokenHandlers(monitor.CurrentValue);
        }

        public IEnumerable<SecurityTokenHandler> GetAllSecurityTokenHandlers()
            => _handlersByType.Values;

        public SecurityTokenHandler GetSecurityTokenHandler(SecurityToken token)
            => GetSecurityTokenHandler(token?.GetType());

        public SecurityTokenHandler GetSecurityTokenHandler(Type tokenType)
            => _handlersByType.TryGetValue(tokenType, out var handler) ? handler : null;

        public SecurityTokenHandler GetSecurityTokenHandler(string tokenTypeIdentifier)
            => _handlersByTokenTypeIdentifier.TryGetValue(tokenTypeIdentifier, out var handler) ? handler : null;

        private void UpdateSecurityTokenHandlers(WsTrustOptions options)
        {
            var handlersByTokenTypeIdentifier = new Dictionary<string, SecurityTokenHandler>();
            var handlersByType = new Dictionary<Type, SecurityTokenHandler>();
            foreach(var descriptor in options.SecurityTokenHandlers)
            {
                var handler = descriptor.Factory(_services);
                if (!(handler is AsyncSecurityTokenHandler))
                {
                    // TODO: Remove wrapper if/when our PR for CanWriteSecurityToken default implementation gets accepted and released.
                    // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/1438
                    handler = new SecurityTokenHandlerWrapper(handler);
                }
                handlersByType.Add(handler.TokenType, handler);
                foreach (var identifier in descriptor.TokenTypeIdentifiers)
                    handlersByTokenTypeIdentifier.Add(identifier, handler);
            }

            _handlersByType = new ReadOnlyDictionary<Type, SecurityTokenHandler>(handlersByType);
            _handlersByTokenTypeIdentifier = new ReadOnlyDictionary<string, SecurityTokenHandler>(handlersByTokenTypeIdentifier);
        }

        public void Dispose() => _optionsChangeToken.Dispose();
    }
}
