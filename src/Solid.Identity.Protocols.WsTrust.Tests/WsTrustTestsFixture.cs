using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Solid.Http;
using Solid.Identity.Protocols.WsTrust.Tests.Host;
using Solid.Testing.AspNetCore.Extensions.XUnit;
using Solid.Testing.AspNetCore.Extensions.XUnit.Soap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Xunit.Abstractions;

#if NET472
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
#elif NETCOREAPP3_1
using Microsoft.IdentityModel.Tokens;
#endif

namespace Solid.Identity.Protocols.WsTrust.Tests
{
    public class WsTrustTestsFixture : SoapTestingServerFixture<Startup>
    {
        public const string SamlTokenType = "urn:oasis:names:tc:SAML:1.0:assertion";
        public const string Saml2TokenType = "urn:oasis:names:tc:SAML:2.0:assertion";

        public static readonly string ClientCertificateBase64 = "MIIKQQIBAzCCCf0GCSqGSIb3DQEHAaCCCe4EggnqMIIJ5jCCBg8GCSqGSIb3DQEHAaCCBgAEggX8MIIF+DCCBfQGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAha4bzbvP78zQICB9AEggTYlB0h4IDG4EkjdZFgFIAq5tXZLKKLPJOzyB5CLpzQV/gfEu7RhWmgjtLwk0+1OiQZD6k39ILuxz2KFVs/gE6R6CAVebW6IIR3RvjGHiAZDU2lcyz5ldN2rK6McdFk8If4eIVad9RSfB4mgnFkoAiY2JpQjjTCaTFoO+Tib1vcWqEFFqtDZdbRLv93hK2nYLK/kO6kKY43QYKj9sqVVyhLNZpIZiVepoYPUuMaez3t6sxzW34SUJv3pr/KQUTIMvtC897JNyQh3OT9MgLXlF3ZxWRCC1+QPwr6/pZwyp4HQEHy0X4NJSKYZHV8ZqL7Qg0n5HfoO5+t1M2Fp1yZjND1YGsKs8WdmMNdrjgF3EBb5xyAu2d8Lsd/y+ivpMZrArDbn2JRF1LpgOwMubl8tdFzyeluFlFRh79eO93KnIES3cmM3Kx0TG7qtQmsWCFCpvwEf7FK6B7WUnn2NbTBiGqrvSthF1QSzVm24lRnfs6I/0IY7gz07Eqwr7AAJM1Bd27tvhQwXT1poNU6e/RyUv0A197072XnYG3GtE7sZe5B12W2UQG8u35ZF93HgPtK0sf5K9Li2sezG8pziy9hwSRJSn4iUnxSu65r+Ox41+dI3nK16oNtZzZ0s7KhjSPFKZ1ylWI1QXVJInSpEpQG61pyHO6Y3Daa55AuNpT28kp+UZbowtHtySivuwfSWHJ0MUK+iTXAsDB5H283BLGLN84dDSXFPF0zQPjMwrQm+pZR41k3r7kWR8+5m6p/YILKmJHaNLMGiytcYa22R3Ooc4doaa40vyr95CsJkfb4VsAqXkx1Nq7yEUHoFkxyg36SVrmXn+2IDy0qJsAJpllx+vSdY1ElVMEcx4aWzlH5F3DaRNGhjgxlEXW32QCuKlBTiUptCVdi+U+JaMlQBXGJdugbPPTzFC1ohvz9mRpD20F8FDn0l6Qn0WZVfZgvWIPB4STW/vlMXsFkSMOx8u2miyxKm7JJUpfcOWFtRF52Qyk4YYU90IZbORjFRg5kIK9Mgm+2UypPNi8J/6uNzuiUxUdquUF1wyYQ+LPnafiJqjodR54POlczkeJ+03iR2bpjvS6x75OSnZgqwAe4wQmRxgeeBASFZ23aNnrcdmwGGJjdn0KCvqvcjMN0mQXsX1xO7OiwV4b9z63EQlWdxecoPMjBQxWpw7DI753WoFcpVTarZmixSc22rgu/xqbj7oMdNXfjz/FgjRNzpHqWGQWffHBLw1I8QL0ioNTQO2rF+QmILoTSQJGnjm17Yft/7JdzVtk96kTWHGPFzrtL59Uq5qOTaVNYwDRUx2K9/UWdcijYG+GOyJRzT6zdO+ryyUZO6xp5L5nVhLMFghuxg6pyiILgdWNTXuippwmBfx6dJy9JuYILO5gNh2BblY61mmDUQr254KhBzCwX8qb12KCIocPnXPt/macRUTeKxYOpsBWSsoHlqPxhmSXL0zrmtJdZ70MrGhv3LG5hwwseTwKxYLg2RXVmp6JulwPtu3GkCR5WDwk3zszkzyZ1yGiubSQ3do79UtkbFDpdBwfE+X1a5UEUBqcs7Yk4i5ygJprrr08byEIR0Cb+zAmd6s3IKpBKpKx2hngSPds3rrXukly6Fbpp4baqkitHkQye4KIg9TC5WpAzjX3PbeLlTjGB4jANBgkrBgEEAYI3EQIxADATBgkqhkiG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAZQAtADkANgBiAGIAYgBkAGMAMQAtADgAOAA1ADYALQA0ADQAMwBlAC0AYQBiAGMAMwAtADcAZABmADYANABkAGQAZgA2AGQAYwAyMF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAHQAcgBvAG4AZwAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIwggPPBgkqhkiG9w0BBwagggPAMIIDvAIBADCCA7UGCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECCry1LcnEYflAgIH0ICCA4goG95QldAZhPJYpQmv/Y47NtVauMbMj27BCRV41zb89+an9FNWBJeX7Z1qSYBJW6TlqBRKmioM/sbiCrDa/EdDDTVef8aCIc66M/+WWU30ke5a9IMyp5GZsPfEG7rKQ7Q/mu3pb0T4kC6PwMxUTfhipO5rONTGiJ1XoCfylckfftwSgY+0/k42loSbiFbtyTJlhA+ZYzQjs+3EC5iUUxPTNE8DsRkcpsVtMkr72MPRItN4u3w+YtzTwiSJ4MOBKP/JUcyc/M7fRXOR+1BfSRqY4Etz3uAyIf8FtOTG27v1GOm4FrOtTAP2bgXWwWIvTIrnN4sKnbnXrLKcfsV0peLFTnDQ99tepGaoAkQpW4qelteZcw2hrVkcNY+aXEX29ncjGHaFmvijOkm4ErTxvwbEk/AqWr2SqQLKzhEsOu3+RR3iCIcnUixDqlu1a5Z/OgboiAWJ9ifOhwF85Ifz74Q0ZZbyZh8erg4nPbsFAYX1ax8VSi6xH0nyAzdhKoSwU6H+UEEIGKsQE2vKftLrXa/CKrcEUCxCnh397NoSOXAoXrvaSruYHRy348Ou7LeYevmoOK00biYlrBi+hfwMwKHXYSNl+jX4oudOqWdLrQEVaZ3DWv9PL9PBZW8CKN7v5xcdkXRfjcsuKgowVtp5IXsr/v+xGRZi5+cCuWM4ufgREWunHfDI/0RJvOMyGMi06gTZmRBNkRPMbXJbwujcgtOoXIzPCTpEDO+BXcw1b2XFsuJIMiQuPlQHO4YTI+rrWVRHef5kKjtbmQ2wFg2+cTWvfCXTbZqLX/k/av0yyhBBV93PUy0wv4jCiT3/7ei9TZveKUPtYSnYGE1iWzYjiD/3GPlioTvGk5PTZeHS79WfWqc1O3oxmFEn5TYZNii8EH5m/7QgRfgjv3wip4XvaCtC5+2noBBHqn1eZPd5bZOktrD/GMBH7dMnNiY21oDh/4+ITxKr+yc1WRWPeToYgMzZvegTuzOHzTaFpOztrp9AWycza3idl/JX0KHeZOwGU+MsxGjS1lVcWDeLKBU0VvQQ0WoZHyRD2aH8DFmv4gxXBrfQ/0dv58TU0WMWvVPt+aAxGUWmWR87uiUs8BpYFyLaZI36PQLiu7xGMfzUsKYU5qpwJmtSZQ9Wf5VcICi1VtsvVO1aoP4y1511kguz3b2GEdafTxRHj3Do355jRC9OVYYlhNKwC33nMDswHzAHBgUrDgMCGgQUtBCG3bL1iMzJxur41t20QkDoPeEEFPMV7OhkkG2SgXaoWWAUsAUaJkWOAgIH0A==";
        public static readonly string CertificteBase64 = "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";

        public X509Certificate2 Certificate { get; }
        public X509Certificate2 ClientCertificate { get; }

        private SecurityTokenHandlerCollection _handlers;

        public WsTrustTestsFixture()
        {
            Certificate = new X509Certificate2(Convert.FromBase64String(CertificteBase64));
            ClientCertificate = new X509Certificate2(Convert.FromBase64String(ClientCertificateBase64));

            _handlers = new SecurityTokenHandlerCollection();
            _handlers.Add(new SamlSecurityTokenHandler());
            _handlers.Add(new Saml2SecurityTokenHandler());
            _handlers.Add(new GodSecurityTokenHandler());
        }

        protected override void ConfigureServices(IServiceCollection services)
        {
            services.ConfigureWsTrust(options => options.DefaultSigningKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(Certificate));
        }

        protected override void ConfigureAppConfiguration(IInMemoryConfigurationBuilderRoot builder)
        {
            builder
                .IncludeLoggingScopes(true)
                .SetDefaultLogLevel(LogLevel.Trace)
                .SetLogLevel("Microsoft", LogLevel.Debug)
                .SetLogLevel("Microsoft.AspNetCore.Hosting", LogLevel.Debug)
                .SetLogLevel("Microsoft.AspNetCore.Hosting.Internal", LogLevel.Information)
                .SetLogLevel("Solid", LogLevel.Trace)
                .SetLogLevel("Microsoft.AspNetCore.DataProtection", LogLevel.None)
            ;
        }
        
        public IWSTrustChannelContract CreateWsTrust13CertificateClient(X509Certificate2 certificate, XmlWriterSettings writerSettings = null, SecurityAlgorithmSuite securityAlgorithmSuite = null)
        {
            var properties = new Dictionary<string, object>
            {
                { "certificate", certificate }
            };
            if (writerSettings != null)
                properties.Add("settings", writerSettings);
            if (securityAlgorithmSuite != null)
                properties.Add("securityAlgorithmSuite", securityAlgorithmSuite);

            var context = SoapChannelCreationContext.Create<IWSTrustChannelContract>(path: "trust/13", MessageVersion.Default, reusable: false, properties: properties);
            var channel = CreateChannel<IWSTrustChannelContract>(context);
            return channel;
        }

        public IWSTrustChannelContract CreateWsTrust13IssuedTokenClient(string subject, string clientTokenType = Saml2TokenType, string appliesTo = "urn:test", string issuer = "test_issuer", SecurityAlgorithmSuite securityAlgorithmSuite = null)
        {
            var identity = CreateIdentity(subject);
            var token = CreateSecurityToken(identity, clientTokenType, appliesTo, issuer);
            var handler = _handlers[clientTokenType];
            var properties = new Dictionary<string, object>
            {
                { "token", token },
                { "handler", handler }
            };
            if (securityAlgorithmSuite != null)
                properties.Add("securityAlgorithmSuite", securityAlgorithmSuite);
            var context = SoapChannelCreationContext.Create<IWSTrustChannelContract>(path: "trust/13", MessageVersion.Default, reusable: false, properties: properties);
            var channel = CreateChannel<IWSTrustChannelContract>(context);
            return channel;
        }

        public IWSTrustChannelContract CreateWsTrust13UserNameClient(string userName, string password, string appliesTo = "urn:test", string issuer = "test_issuer", SecurityAlgorithmSuite securityAlgorithmSuite = null)
        {
            var properties = new Dictionary<string, object>
            {
                { "userName", userName },
                { "password", password }
            };
            if (securityAlgorithmSuite != null)
                properties.Add("securityAlgorithmSuite", securityAlgorithmSuite);
            var context = SoapChannelCreationContext.Create<IWSTrustChannelContract>(path: "trust/13", MessageVersion.Default, reusable: false, properties: properties);
            var channel = CreateChannel<IWSTrustChannelContract>(context);
            return channel;
        }

        //public IWSTrustChannelContract CreateWsTrust13CertificateClient(X509Certificate2 certificate)
        //{
        //    var properties = new Dictionary<string, object>
        //    {
        //        { "certificate", certificate }
        //    };
        //    var context = SoapChannelCreationContext.Create<IWSTrustChannelContract>(path: "trust/13", MessageVersion.Default, reusable: false, properties: properties);
        //    var channel = CreateChannel<IWSTrustChannelContract>(context);
        //    return channel;
        //}

        public T ConvertSecurityToken<T>(SecurityToken token)
            where T : SecurityToken => ConvertSecurityToken(token, typeof(T)) as T;

        public SecurityToken ConvertSecurityToken(SecurityToken token, Type to)
        {
            var type = token?.GetType();
            if (type == null) return null;
            if (to.IsAssignableFrom(type)) return token;
            if (token is GenericXmlSecurityToken xmlToken)
            {
                var xml = xmlToken.TokenXml.OuterXml;
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
                {
                    using (var reader = XmlReader.Create(stream))
                    {
                        reader.MoveToContent();
                        if (!_handlers.CanReadToken(reader)) throw new InvalidOperationException("Cannot read token.");
                        return _handlers.ReadToken(reader);
                    }
                }
            }
            throw new ArgumentException($"Cannot convert from {type.Name} to {to.Name}.");
        }

        protected override EndpointAddress CreateEndpointAddress<TChannel>(Uri url, SoapChannelCreationContext context)
            => new EndpointAddress(url, new DnsEndpointIdentity(url.Host), new AddressHeaderCollection());
        
        protected override Binding CreateBinding<TChannel>(SoapChannelCreationContext context)
        {
            var binding = null as Binding;
            if (context.Properties.TryGetValue("handler", out var handler))
                binding = CreateFederationBinding(handler as SecurityTokenHandler, context);
            else if (context.Properties.TryGetValue("userName", out _) && context.Properties.TryGetValue("password", out _))
                binding = CreateBinding(MessageCredentialType.UserName, context);
            else if (context.Properties.TryGetValue("certificate", out _))
                binding = CreateBinding(MessageCredentialType.Certificate, context);

            binding.ReceiveTimeout = TimeSpan.FromMinutes(10);
            binding = binding.WithoutTransportSecurity();
            
            if(context.Properties.TryGetValue("settings", out var writerSettings))
                binding = binding.WithSolidHttpTransport(TestingServer, writerSettings: writerSettings as XmlWriterSettings);
            return binding;
        }

        private Binding CreateBinding(MessageCredentialType credentialType, SoapChannelCreationContext context)
        {
            var binding = new WS2007HttpBinding(SecurityMode.TransportWithMessageCredential);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.ClientCredentialType = credentialType;

            if(context.Properties.TryGetValue("securityAlgorithmSuite", out var value) && value is SecurityAlgorithmSuite securityAlgorithmSuite)
                binding.Security.Message.AlgorithmSuite = securityAlgorithmSuite;

            return binding;
        }

        private Binding CreateFederationBinding(SecurityTokenHandler handler, SoapChannelCreationContext context)
        {
            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            binding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.IssuedTokenType = handler.GetTokenTypeIdentifiers().FirstOrDefault();

            if (context.Properties.TryGetValue("securityAlgorithmSuite", out var value) && value is SecurityAlgorithmSuite securityAlgorithmSuite)
                binding.Security.Message.AlgorithmSuite = securityAlgorithmSuite;

            return binding;
        }

        protected override ChannelFactory<TChannel> CreateChannelFactory<TChannel>(Binding binding, EndpointAddress endpointAddress, SoapChannelCreationContext context)
        {
            var factory = new WSTrustChannelFactory(binding, endpointAddress);
            factory.TrustVersion = TrustVersion.WSTrust13;
            if (context.Properties.TryGetValue("handler", out var handler))
            {
                factory.Credentials.UseIdentityConfiguration = true;
                factory.Credentials.SupportInteractive = false;
                var handlers = factory.Credentials.SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.Default];
                handlers.AddOrReplace(handler as SecurityTokenHandler);
            }
            return factory as ChannelFactory<TChannel>;
        }

        protected override ICommunicationObject CreateChannel<TChannel>(ChannelFactory<TChannel> factory, SoapChannelCreationContext context)
        {
            if(factory is WSTrustChannelFactory wsTrust)
            {
                if (context.Properties.TryGetValue("userName", out var userName) && context.Properties.TryGetValue("password", out var password))
                {
                    wsTrust.Credentials.UserName.UserName = userName as string;
                    wsTrust.Credentials.UserName.Password = password as string;
                    return wsTrust.CreateChannel() as ICommunicationObject;
                }
                else if (context.Properties.TryGetValue("certificate", out var certificate))
                {
                    wsTrust.Credentials.ClientCertificate.Certificate = certificate as X509Certificate2;
                    return wsTrust.CreateChannel() as ICommunicationObject;
                }
                else if(context.Properties.TryGetValue("token", out var token))
                return wsTrust.CreateChannelWithIssuedToken(token as SecurityToken) as ICommunicationObject;
            }
            return base.CreateChannel<TChannel>(factory, context);
        }

        private ClaimsIdentity CreateIdentity(string username)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Name, username)
            };
            return new ClaimsIdentity(claims, "Federated", ClaimTypes.NameIdentifier, ClaimTypes.Role);
        }

        private SecurityToken CreateSecurityToken(ClaimsIdentity identity, string tokenTypeIdentifier, string appliesTo, string issuer)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                AppliesToAddress = appliesTo,
                TokenIssuerName = issuer,
                SigningCredentials = new X509SigningCredentials(Certificate),
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddHours(1)),
                Subject = identity,
                TokenType = tokenTypeIdentifier
            };
            return _handlers.CreateToken(descriptor);
        }
    }
}
