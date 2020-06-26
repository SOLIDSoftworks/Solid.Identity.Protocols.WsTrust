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
using Solid.Identity.Tokens;

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

                    .AddIdentityProvider("urn:test:issuer", idp =>
                    {
                        using (var certificate = new X509Certificate2(Convert.FromBase64String(Certificates.ClientCertificateBase64)))
                        {
                            var publicCertificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));
                            idp.AllowedRelyingParties.Add(new Uri("urn:tests"));
                            idp.SecurityKey = new X509SecurityKey(publicCertificate);
                        }
                    })
                    .AddRelyingParty("urn:tests", party =>
                    {
                        var certificate = new X509Certificate2(Convert.FromBase64String(Certificates.RelyingPartyValidBase64));
                        party.Name = "My test relying party";
                        party.SigningKey = new X509SecurityKey(certificate);
                        party.SigningAlgorithm = SecurityAlgorithm.Asymmetric.RsaSha256;
                        party.TokenType = Saml2Constants.Saml2TokenProfile11;
                    })

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
