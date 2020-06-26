using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust;
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

        public WsTrustBuilder AddSecurityTokenService<TSecurityTokenService>(Func<IServiceProvider, TSecurityTokenService> factory)
            where TSecurityTokenService : SecurityTokenService
        {
            Services.AddTransient<SecurityTokenService>(factory);
            return this;
        }

        public WsTrustBuilder AddSecurityTokenService<TSecurityTokenService>()
            where TSecurityTokenService : SecurityTokenService
        {
            Services.AddTransient<SecurityTokenService, TSecurityTokenService>();
            return this;
        }

        public WsTrustBuilder AddPasswordValidator<TPasswordValidator>()
            where TPasswordValidator : class, IPasswordValidator
        {
            Services.AddSingleton<IPasswordValidator, TPasswordValidator>();
            return this;
        }

        public WsTrustBuilder AddX509Certificate2Validator<TX509Certificate2Validator>()
            where TX509Certificate2Validator : class, IX509Certificate2Validator
        {
            Services.AddSingleton<IX509Certificate2Validator, TX509Certificate2Validator>();
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
    }
}
