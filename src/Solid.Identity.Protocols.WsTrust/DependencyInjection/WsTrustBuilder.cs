using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Solid.Identity.DependencyInjection
{
    public class WsTrustBuilder
    {
        internal WsTrustBuilder(IServiceCollection services)
        {
            Services = services;
        }

        public IServiceCollection Services { get; }

        public WsTrustBuilder Configure(Action<WsTrustOptions> configureOptions)
        {
            Services.Configure(configureOptions);
            return this;
        }

        public WsTrustBuilder AddWsTrust13AsyncContract()
        {
            Services.TryAddSingleton<WsTrustService>();
            Services.AddSingletonSoapService<IWsTrust13AsyncContract>(p => p.GetService<WsTrustService>());
            return this;
        }

        public WsTrustBuilder AddWsTrust13SyncContract()
        {
            Services.TryAddSingleton<WsTrustService>();
            Services.AddSingletonSoapService<IWsTrust13AsyncContract>(p => p.GetService<WsTrustService>());
            return this;
        }

        public WsTrustBuilder AddTokenValidationParametersFactory<TTokenValidationParametersFactory>(Func<IServiceProvider, TTokenValidationParametersFactory> factory)
            where TTokenValidationParametersFactory : class, ITokenValidationParametersFactory
        {
            Services.TryAddSingleton<ITokenValidationParametersFactory>(factory);
            return this;
        }

        public WsTrustBuilder AddTokenValidationParametersFactory<TTokenValidationParametersFactory>()
            where TTokenValidationParametersFactory : class, ITokenValidationParametersFactory
        {
            Services.TryAddSingleton<ITokenValidationParametersFactory, TTokenValidationParametersFactory>();
            return this;
        }

        public WsTrustBuilder AddSecurityTokenService<TSecurityTokenService>(Func<IServiceProvider, TSecurityTokenService> factory)
            where TSecurityTokenService : SecurityTokenService
        {
            Services.TryAddTransient<SecurityTokenService>(factory);
            return this;
        }

        public WsTrustBuilder AddSecurityTokenService<TSecurityTokenService>()
            where TSecurityTokenService : SecurityTokenService
        {
            Services.TryAddTransient<SecurityTokenService, TSecurityTokenService>();
            return this;
        }

        public WsTrustBuilder AddPasswordValidator<TPasswordValidator>()
            where TPasswordValidator : class, IPasswordValidator
        {
            Services.TryAddSingleton<IPasswordValidator, TPasswordValidator>();
            return this;
        }

        public WsTrustBuilder AddX509Validator<TX509Validator>()
            where TX509Validator : class, IX509Validator
        {
            Services.TryAddSingleton<IX509Validator, TX509Validator>();
            return this;
        }

        public WsTrustBuilder AddRelyingPartyStore<TRelyingPartyStore>(Func<IServiceProvider, TRelyingPartyStore> factory)
            where TRelyingPartyStore : class, IRelyingPartyStore
        {
            Services.TryAddSingleton<IRelyingPartyStore>(factory);
            return this;
        }

        public WsTrustBuilder AddRelyingPartyStore<TRelyingPartyStore>()
            where TRelyingPartyStore : class, IRelyingPartyStore
        {
            Services.TryAddSingleton<IRelyingPartyStore, TRelyingPartyStore>();
            return this;
        }

        public WsTrustBuilder AddIdentityProviderStore<TIdentityProviderStore>(Func<IServiceProvider, TIdentityProviderStore> factory)
            where TIdentityProviderStore : class, IIdentityProviderStore
        {
            Services.TryAddSingleton<IIdentityProviderStore>(factory);
            return this;
        }

        public WsTrustBuilder AddIdentityProviderStore<TIdentityProviderStore>()
            where TIdentityProviderStore : class, IIdentityProviderStore
        {
            Services.TryAddSingleton<IIdentityProviderStore, TIdentityProviderStore>();
            return this;
        }

        public WsTrustBuilder AddIncomingClaimMapper<TMapper>()
            where TMapper : class, IClaimMapper
        {
            Services.TryAddEnumerable(ServiceDescriptor.Transient<IClaimMapper, TMapper>());
            return this;
        }

        public WsTrustBuilder AddIncomingClaimMapper<TMapper>(Func<IServiceProvider, TMapper> factory)
            where TMapper : class, IClaimMapper
        {
            Services.TryAddEnumerable(ServiceDescriptor.Transient<IClaimMapper, TMapper>(factory));
            return this;
        }

        public WsTrustBuilder AddClaimStore<TStore>()
            where TStore : class, IClaimStore
        {
            Services.TryAddEnumerable(ServiceDescriptor.Transient<IClaimStore, TStore>());
            return this;
        }

        public WsTrustBuilder AddClaimStore<TStore>(Func<IServiceProvider, TStore> factory)
            where TStore : class, IClaimStore
        {
            Services.TryAddEnumerable(ServiceDescriptor.Transient<IClaimStore, TStore>(factory));
            return this;
        }
    }
}
