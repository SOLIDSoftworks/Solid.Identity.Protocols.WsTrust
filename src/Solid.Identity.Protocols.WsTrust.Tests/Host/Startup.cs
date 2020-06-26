using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.Identity.Protocols.WsTrust.Tests.Host.Tokens;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Tests.Host
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;

            services.AddLogging(builder => builder.AddDebug());
            services.AddWsTrust13AsyncService(builder =>
            {
                var god = new Tokens.GodSecurityTokenHandler();
                builder
                    .AddPasswordValidator<TestPasswordValidator>()
                    .AddX509Certificate2Validator<TestX509Certificate2Validator>()

                    .AddSecurityTokenService<TestSecurityTokenService>()
                    .AddSecurityTokenHandler(new SamlSecurityTokenHandler(), SamlConstants.Saml11Namespace)
                    .AddSecurityTokenHandler(new Saml2SecurityTokenHandler(), Saml2Constants.Saml2TokenProfile11)
                    .AddSecurityTokenHandler(god, god.GetTokenTypeIdentifiers())

                    .AddSha1()
                    .AddSha1WithRsa()

                    .Configure(options =>
                    {
                        options.Issuer = "urn:Solid.Identity.Protocols.WsTrust.Tests.Host";
                    })
                ;
            });
        }

        public void Configure(IApplicationBuilder builder)
        {
            builder.UseWsTrust13AsyncService();
        }
    }
}
