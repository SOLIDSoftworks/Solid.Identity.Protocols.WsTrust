#if NETCOREAPP3_1
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsSecurity.Middleware;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class EndpointBuilderExtensions
    {
        public static IEndpointRouteBuilder MapWsTrust13AsyncService(this IEndpointRouteBuilder builder)
            => builder.MapWsTrust13AsyncService("/trust/13");
        public static IEndpointRouteBuilder MapWsTrust13AsyncService(this IEndpointRouteBuilder builder, PathString path)
        {
            builder.ServiceProvider.InitializeCustomCryptoProvider();

            builder.MapSoapService<IWsTrust13AsyncContract>(path, MessageVersion.Soap12WSAddressing10, soap =>
            {
                soap.UseMiddleware<WsSecurityMiddleware>();
            });
            return builder;
        }
    }
}
#endif