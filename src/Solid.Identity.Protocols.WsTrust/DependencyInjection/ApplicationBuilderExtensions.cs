using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Solid.Identity.Protocols.WsSecurity.Middleware;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class Solid_Identity_Protocols_WsTrust_ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseWsTrust13AsyncService(this IApplicationBuilder builder)
            => builder.UseWsTrust13AsyncService("/trust/13");


        public static IApplicationBuilder UseWsTrust13AsyncService(this IApplicationBuilder builder, PathString pathPrefix)
        {
            builder.MapSoapService<IWsTrust13AsyncContract>(pathPrefix, app =>
            {
                app.UseMiddleware<WsSecurityMiddleware>();
            });
            return builder;
        }
    }
}
