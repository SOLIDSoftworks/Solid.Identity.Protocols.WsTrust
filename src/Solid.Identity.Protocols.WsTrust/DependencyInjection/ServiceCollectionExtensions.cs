using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.DependencyInjection;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsSecurity.Authentication;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.Defaults;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class Solid_Identity_Protocols_WsTrust_ServiceCollectionExtensions
    {
        public static IServiceCollection ConfigureWsTrust(this IServiceCollection services, Action<WsTrustOptions> configureOptions)
            => services.Configure(configureOptions);

        //public static IServiceCollection AddCryptoProvider(this IServiceCo)

        public static IServiceCollection AddWsTrust13AsyncService(this IServiceCollection services, Action<WsTrustBuilder> configure)
            => services.AddWsTrustService<IWsTrust13AsyncContract, WsTrustService>(configure);

        private static IServiceCollection AddWsTrustService<TContract, TService>(this IServiceCollection services, Action<WsTrustBuilder> configure)
            where TService : class, TContract
            where TContract : class
        {
            services.TryAddSingleton<TService>();
            services.AddSingletonSoapService<TContract>(p => p.GetService<TService>(), service =>
            {
                service
                    .Services
                    .AddAuthentication()
                    .AddScheme<AuthenticationSchemeOptions, WsSecurityAuthenticationHandler>(
                        service.Contract.FullName,
                        $"WS-Security ({service.Contract.FullName})",
                        _ => { }
                    )
                ;
                var builder = new WsTrustBuilder(service);
                configure(builder);
                builder.AddSecurityTokenService<SecurityTokenService>();
                builder.AddTokenValidationParametersFactory<WsTrustTokenValidationParametersFactory>();
                builder.AddIdentityProviderStore<DefaultIdentityProviderStore>();
                builder.AddRelyingPartyStore<DefaultRelyingPartyStore>();
            });
            services.TryAddTransient<IncomingClaimsMapper>();
            services.TryAddTransient<OutgoingSubjectFactory>();
            services.TryAddSingleton<WsTrustSerializerFactory>();
            services.TryAddSingleton<SecurityTokenServiceFactory>();
            services.TryAddSingleton<SecurityTokenHandlerProvider>();
            services.TryAddSingleton<UserNameSecurityTokenHandler>();
            services.TryAddSingleton<X509SecurityTokenHandler>();
            services.TryAddSingleton<X509SecurityTokenHandler>();

            return services;
        }
    }
}
