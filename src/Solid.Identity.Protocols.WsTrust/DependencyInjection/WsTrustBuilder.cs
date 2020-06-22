using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Linq;
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
            Configure(o => o.SecurityTokenHandlers.Add(new SecurityTokenHandlerDescriptor(requestedTokenTypes, factory))); ;
            return this;
        }
    }
}
