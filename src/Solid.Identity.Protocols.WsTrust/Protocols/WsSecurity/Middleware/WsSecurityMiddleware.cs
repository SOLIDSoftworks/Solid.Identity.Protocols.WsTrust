using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Extensions.AspNetCore.Soap.Middleware;
using Solid.Identity.Protocols.WsSecurity.Headers;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;

namespace Solid.Identity.Protocols.WsSecurity.Middleware
{
    internal class WsSecurityMiddleware : SoapMiddleware
    {
        private ISystemClock _clock;

        public WsSecurityMiddleware(ISystemClock clock, RequestDelegate next, ILogger<WsSecurityMiddleware> logger) 
            : base(next, logger)
        {
            _clock = clock;
        }

        protected override async ValueTask InvokeAsync(SoapContext context)
        {
            var contract = context.Contract;
            var authentication = context.RequestServices.GetService<IAuthenticationService>();
            var result = await authentication.AuthenticateAsync(context.HttpContext, contract.FullName);
            if (result.Failure != null)
                throw result.Failure;
            if(result.Succeeded)
                // TODO: map incoming claims
                context.User = result.Principal;
            await Next(context);

            if (context.Response?.IsFault == false)
            {
                var created = _clock.UtcNow.UtcDateTime;
                var expires = created.AddMinutes(5); // TODO: add an option for this
                context.Response.Headers.Add(new TimestampMessageHeader(created, expires));
            }
        }

    }
}
