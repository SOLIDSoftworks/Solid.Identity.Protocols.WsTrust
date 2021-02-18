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
using Solid.ServiceModel.Security;
using Solid.IdentityModel.Tokens.Xml;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.Identity.Protocols.WsTrust.Tests.Host.Tokens;

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
        public const string Issuer = "urn:Solid.Identity.Protocols.WsTrust.Tests.Host";

        public X509Certificate2 Certificate { get; }
        public X509Certificate2 ClientCertificate { get; }

        private IDictionary<string, SecurityTokenHandler> _handlers;

        public WsTrustTestsFixture()
        {
            Certificate = new X509Certificate2(Convert.FromBase64String(Certificates.SigningCertificteBase64));
            ClientCertificate = new X509Certificate2(Convert.FromBase64String(Certificates.ClientCertificateBase64));

            var saml = new SamlSecurityTokenHandler();
            var saml2 = new Saml2SecurityTokenHandler();
            var god = new GodSecurityTokenHandler();
            _handlers = new Dictionary<string, SecurityTokenHandler>
            {
                { SamlTokenType, saml },
                { Saml2TokenType, saml2 },
                { "urn:god", god },
                { "urn:deity", god }
            };
        }

        protected override void ConfigureServices(IServiceCollection services)
        {
            services.ConfigureWsTrust(options =>
            {
                options.Issuer = Issuer;
                options.DefaultSigningKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(Certificate);
            });
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
        
        public IWsTrustChannelContract CreateWsTrust13CertificateClient(X509Certificate2 certificate, XmlWriterSettings writerSettings = null, SecurityAlgorithmSuite securityAlgorithmSuite = null)
        {
            var properties = new Dictionary<string, object>
            {
                { "certificate", certificate }
            };
            if (writerSettings != null)
                properties.Add("settings", writerSettings);
            if (securityAlgorithmSuite != null)
                properties.Add("securityAlgorithmSuite", securityAlgorithmSuite);

            var context = SoapChannelCreationContext.Create<IWsTrustChannelContract>(path: "trust/13", MessageVersion.Default, reusable: false, properties: properties);
            var channel = CreateChannel<IWsTrustChannelContract>(context);
            return channel;
        }

        public IWsTrustChannelContract CreateWsTrust13IssuedTokenClient(string subject, string clientTokenType = Saml2TokenType, string appliesTo = "urn:tests", string issuer = "urn:test:issuer", SecurityAlgorithmSuite securityAlgorithmSuite = null)
        {
            var identity = CreateIdentity(subject);
            var token = CreateSecurityToken(identity, clientTokenType, appliesTo, issuer);
            if (!_handlers.TryGetValue(clientTokenType, out var handler))
                throw new Exception($"Security handler not found for '{clientTokenType}'");
            var properties = new Dictionary<string, object>
            {
                { "token", token },
                { "handler", handler }
            };
            if (securityAlgorithmSuite != null)
                properties.Add("securityAlgorithmSuite", securityAlgorithmSuite);
            var context = SoapChannelCreationContext.Create<IWsTrustChannelContract>(path: "trust/13", MessageVersion.Default, reusable: false, properties: properties);
            var channel = CreateChannel<IWsTrustChannelContract>(context);
            return channel;
        }

        public IWsTrustChannelContract CreateWsTrust13UserNameClient(string userName, string password, string appliesTo = "urn:tests", string issuer = "urn:test:issuer", SecurityAlgorithmSuite securityAlgorithmSuite = null)
        {
            var properties = new Dictionary<string, object>
            {
                { "userName", userName },
                { "password", password }
            };
            if (securityAlgorithmSuite != null)
                properties.Add("securityAlgorithmSuite", securityAlgorithmSuite);
            var context = SoapChannelCreationContext.Create<IWsTrustChannelContract>(path: "trust/13", MessageVersion.Default, reusable: false, properties: properties);
            var channel = CreateChannel<IWsTrustChannelContract>(context);
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
                var xml = xmlToken.Element.OuterXml;
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
                {
                    using (var reader = XmlReader.Create(stream))
                    {
                        reader.MoveToContent();
                        foreach(var handler in _handlers.Values.Distinct())
                        {
                            if (!handler.CanReadToken(reader)) continue;
                            return handler.ReadToken(reader);
                        }

                        throw new InvalidOperationException("Cannot read token.");
                    }
                }
            }
            throw new ArgumentException($"Cannot convert from {type.Name} to {to.Name}.");
        }

        protected override EndpointAddress CreateEndpointAddress<TChannel>(Uri url, SoapChannelCreationContext context)
            => new EndpointAddress(url);
        
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
            var binding = new WsTrustIssuedTokenBinding();

            binding.KeyType = System.IdentityModel.Tokens.SecurityKeyType.BearerKey;
            binding.Security.Message.EstablishSecurityContext = false;
            //binding.Security.Message.IssuedTokenType = handler.GetTokenTypeIdentifiers().FirstOrDefault();

            if (context.Properties.TryGetValue("securityAlgorithmSuite", out var value) && value is SecurityAlgorithmSuite securityAlgorithmSuite)
                binding.Security.Message.AlgorithmSuite = securityAlgorithmSuite;

            return binding;
        }

        protected override ChannelFactory<TChannel> CreateChannelFactory<TChannel>(Binding binding, EndpointAddress endpointAddress, SoapChannelCreationContext context)
        {
            var factory = new WsTrustChannelFactory(binding, endpointAddress);
            factory.TrustVersion = WsTrustVersion.Trust13;
            if (context.Properties.TryGetValue("handler", out var handler))
            {
                var other = factory.SecurityTokenHandlers.FirstOrDefault(h => h.GetType() == handler.GetType());
                if (other != null)
                    factory.SecurityTokenHandlers.Remove(other);
                factory.SecurityTokenHandlers.Add(handler as SecurityTokenHandler);
            }
            return factory as ChannelFactory<TChannel>;
        }

        protected override ICommunicationObject CreateChannel<TChannel>(ChannelFactory<TChannel> factory, SoapChannelCreationContext context)
        {
            if(factory is WsTrustChannelFactory wsTrust)
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
                Audience = appliesTo,
                Issuer = issuer,
                SigningCredentials = new X509SigningCredentials(ClientCertificate),
                NotBefore = DateTime.UtcNow,
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddHours(1),
                Subject = identity
            };

            if(!_handlers.TryGetValue(tokenTypeIdentifier, out var handler))
                throw new Exception($"Security handler not found for '{tokenTypeIdentifier}'");

            return handler.CreateToken(descriptor);
        }
    }
}
