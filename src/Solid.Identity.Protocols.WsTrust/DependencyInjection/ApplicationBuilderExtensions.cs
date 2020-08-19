using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsSecurity.Middleware;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class Solid_Identity_Protocols_WsTrust_ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseWsTrust13AsyncService(this IApplicationBuilder builder)
            => builder.UseWsTrust13AsyncService("/trust/13");


        public static IApplicationBuilder UseWsTrust13AsyncService(this IApplicationBuilder builder, PathString pathPrefix)
        {
            builder.ApplicationServices.InitializeCustomCryptoProvider();

            builder.MapSoapService<IWsTrust13AsyncContract>(pathPrefix, app =>
            {
                app.UseMiddleware<WsSecurityMiddleware>();
            });
            return builder;
        }

        internal static void InitializeCustomCryptoProvider(this IServiceProvider services)
        {
            var cryptoProvider = services.GetService<ICryptoProvider>();
            CryptoProviderFactory.Default.CustomCryptoProvider = cryptoProvider;
        }
    }
}
