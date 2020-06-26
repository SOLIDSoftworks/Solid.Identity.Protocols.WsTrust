﻿using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Solid.Identity.DependencyInjection
{
    public class WsTrustBuilder
    {
        internal WsTrustBuilder(SoapServiceBuilder soap)
        {
            Soap = soap;
            Services = soap.Services;
        }

        public SoapServiceBuilder Soap { get; }
        public IServiceCollection Services { get; }

        public WsTrustBuilder Configure(Action<WsTrustOptions> configureOptions)
        {
            Services.Configure(configureOptions);
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

        public WsTrustBuilder AddX509Certificate2Validator<TX509Certificate2Validator>()
            where TX509Certificate2Validator : class, IX509Certificate2Validator
        {
            Services.TryAddSingleton<IX509Certificate2Validator, TX509Certificate2Validator>();
            return this;
        }

        public WsTrustBuilder AddSecurityTokenHandler(SecurityTokenHandler handler, params string[] requestedTokenTypes)
            => AddSecurityTokenHandler(_ => handler, requestedTokenTypes);

        public WsTrustBuilder AddSecurityTokenHandler(Func<IServiceProvider, SecurityTokenHandler> factory, params string[] requestedTokenTypes)
        {
            Configure(o => o.SecurityTokenHandlers.Add(new SecurityTokenHandlerDescriptor(requestedTokenTypes, factory)));
            return this;
        }

        public WsTrustBuilder AddSha1()
            => AddSupportedHashAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1", _ => SHA1.Create());

        public WsTrustBuilder AddSha1WithRsa()
            => AddSupportedSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1", (services, key) =>
            {
                var logger = services.GetRequiredService<ILogger<RsaSha1SignatureProvider>>();
                return new RsaSha1SignatureProvider(key, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", logger);
            });

        public WsTrustBuilder AddSupportedHashAlgorithm(string algorithm, Func<IServiceProvider, HashAlgorithm> factory)
        {
            Services.TryAddSingleton<ICryptoProvider, CustomCryptoProvider>();
            Configure(o => o.SupportedHashAlgorithms[algorithm] = new HashAlgorithmDescriptor(algorithm, (services, __) => factory(services)));
            return this;
        }

        public WsTrustBuilder AddSupportedSignatureAlgorithm(string algorithm, Func<IServiceProvider, SecurityKey, SignatureProvider> factory)
        {
            Services.TryAddSingleton<ICryptoProvider, CustomCryptoProvider>();
            Configure(o => o.SupportedSignatureAlgorithms[algorithm] = new SignatureProviderDescriptor(algorithm, (services, args) => factory(services, args.FirstOrDefault() as SecurityKey)));
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

        public WsTrustBuilder AddRelyingParty(string appliesTo, Action<RelyingParty> configureRelyingParty)
        {
            if (!Uri.TryCreate(appliesTo, UriKind.RelativeOrAbsolute, out var uri))
                throw new ArgumentException("AppliesTo must be a valid Uri.", nameof(appliesTo));
            return AddRelyingParty(uri, configureRelyingParty);
        }

        public WsTrustBuilder AddRelyingParty(Uri appliesTo, Action<RelyingParty> configureRelyingParty)
        {
            var party = new RelyingParty { AppliesTo = appliesTo };
            configureRelyingParty(party);
            Configure(o => o.RelyingParties[appliesTo] = party);
            return this;
        }

        public WsTrustBuilder AddIdentityProvider(string id, Action<IdentityProvider> configureIdentityProvider)
        {
            var idp = new IdentityProvider { Id = id };
            configureIdentityProvider(idp);
            Configure(o => o.IdentityProviders[id] = idp);
            return this;
        }
    }
}
