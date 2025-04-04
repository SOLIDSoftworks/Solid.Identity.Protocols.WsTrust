using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using Solid.Identity.Protocols.WsSecurity.Logging;
using Solid.Identity.Protocols.WsSecurity.Signatures;
using Solid.Identity.Protocols.WsSecurity.Xml;
using Solid.Identity.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace Solid.Identity.Protocols.WsSecurity.Authentication
{
    internal class WsSecurityAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private static readonly XName Timestamp = XName.Get("Timestamp", WsUtilityConstants.WsUtility10.Namespace);
        private static readonly XName Signature = XName.Get("Signature", XmlSignatureConstants.Namespace);

        private ISoapContextAccessor _soapContextAccessor;
        private ITokenValidationParametersFactory _tokenValidationParametersFactory;
        private SecurityTokenHandlerProvider _securityTokenHandlerProvider;

        public WsSecurityAuthenticationHandler(
            ISoapContextAccessor soapContextAccessor,
            IServiceProvider services,
            ITokenValidationParametersFactory tokenValidationParametersFactory,
            SecurityTokenHandlerProvider securityTokenHandlerProvider,

            IOptionsMonitor<AuthenticationSchemeOptions> options, 
            ILoggerFactory logger, 
            UrlEncoder encoder, 
            ISystemClock clock) 
            : base(options, logger, encoder, clock)
        {
            _soapContextAccessor = soapContextAccessor;
            _tokenValidationParametersFactory = tokenValidationParametersFactory;
            _securityTokenHandlerProvider = securityTokenHandlerProvider;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            using var activity = Tracing.WsSecurity.Base.StartActivity($"{nameof(WsSecurityAuthenticationHandler)}.{nameof(HandleAuthenticateAsync)}");
            var soap = _soapContextAccessor.SoapContext;
            if (soap == null) return AuthenticateResult.NoResult();

            var index = soap.Request.Headers.FindHeader("Security", WsSecurityConstants.WsSecurity10.Namespace);
            if (index < 0) return AuthenticateResult.NoResult();

            try
            {
                var results = new List<VerifyTokenResult>();

                var reader = soap.Request.Headers.GetReaderAtHeader(index);
                //if (_wsTrust.ValidateWsSecuritySignatures)
                //    reader = new EnvelopedSignatureReader(reader);

                using (reader)
                {
                    reader.MoveToContent();
                    if(reader.IsWsSecurity())
                        reader.Read();

                    var signature = null as Signature;
                    while (!reader.EOF)
                    {
                        if (reader.IsWsSecurityTimestamp())
                            HandleTimestamp(reader, soap);
                        else if (reader.IsXmlSignature())
                        {
                            if (signature != null)
                                throw new SecurityException("Multiple signatures found in WS-Security header.");

                            signature = ReadSignature(reader, soap);
                        }
                        else if (reader.IsStartElement())
                        {
                            var verified = await VerifyTokenAsync(reader, soap);
                            results.Add(verified);
                        }
                        else if (reader.IsWsSecurityEndElement()) break;
                        else if (reader.NodeType == XmlNodeType.EndElement) reader.Read();
                        else throw new InvalidOperationException("Reader in invalid state.");
                    }
                    if(signature != null)
                    {
                        var uri = signature.KeyInfo.GetSecurityTokenReference()?.Reference.Uri;
                        var key = results
                            .Select(r => r.SecurityToken)
                            .FirstOrDefault(t => $"#{t.Id}" == uri)
                        ;
                        if (key == null)
                            throw new SecurityException($"Unable to find security token '#{uri}'.");
                        if (key.SecurityKey == null)
                            throw new SecurityException($"There is no security key associated with token '#{uri}'.");
                        signature.Verify(key.SecurityKey);
                    }
                }

                var result = results.First();
                var header = soap.Request.Headers[index];
                soap.Request.Headers.UnderstoodHeaders.Add(header);
                var properties = new AuthenticationProperties
                {
                    IsPersistent = false
                };
                properties.Parameters.Add(nameof(SecurityToken), result.SecurityToken);

                AddIssuerClaim(result.User, result.SecurityToken);

                return AuthenticateResult.Success(new AuthenticationTicket(result.User, properties, Scheme.Name));
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex);
            }
        }

        private void AddIssuerClaim(ClaimsPrincipal user, SecurityToken token)
        {
            if (token?.Issuer == null) return;
            var identity = ClaimsPrincipal.PrimaryIdentitySelector(user.Identities);
            identity.AddClaim(new Claim(WsSecurityClaimTypes.Issuer, token.Issuer));
        }

        private Signature ReadSignature(XmlReader reader, SoapContext soap)
        {
            using var activity = Tracing.WsSecurity.Base.StartActivity($"{nameof(WsSecurityAuthenticationHandler)}.{nameof(ReadSignature)}");
            WsSecurityLogMessages.LogSignatureElement(Logger, ref reader);

            using var buffer = soap.Request.CreateBufferedCopy((int)(soap.HttpContext.Request.ContentLength ?? 64 * 1024));
            using var message = buffer.CreateMessage();
            using var stream = new MemoryStream();
           
            using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false }))
                message.WriteMessage(writer);
            stream.Position = 0;
            using (var document = XmlReader.Create(stream))
            {
                var serializer = new WsUtilityDSigSerializer(document);
                var signature = serializer.ReadSignature(reader);
                soap.Request = buffer.CreateMessage();
                return signature;
            }
        }

        //private void ValidateSignatures(SoapContext context, IEnumerable<SecurityToken> tokens)
        //{
        //    using var buffer = context.Request.CreateBufferedCopy((int)(context.HttpContext.Request.ContentLength ?? 64 * 1024));
        //    using var request = buffer.CreateMessage();

        //    using var stream = new MemoryStream();
            
        //    using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false }))
        //        request.WriteMessage(writer);

        //    stream.Position = 0;

        //    using (var reader = new EnvelopedSignatureReader(XmlReader.Create(stream)))
        //        _ = reader.ReadOuterXml();
            
        //    context.Request = buffer.CreateMessage();
        //}

        //private AsymmetricAlgorithm GetPublicKey(SoapContext context, KeyInfo keyInfo, IEnumerable<SecurityToken> tokens)
        //{
        //    keyInfo.
        //    var inner = keyInfo.GetXml().ChildNodes.OfType<XmlElement>().First();
        //    if (inner.LocalName != "SecurityTokenReference" || inner.NamespaceURI != WsSecurityConstants.WsSecurity10Namespace) return null;

        //    var children = inner.Elements();
        //    if (!children.Any()) throw context.CreateFailedCheckFault();

        //    var first = children.First();
        //    if (first.LocalName == "Reference" && first.NamespaceURI == WsSecurityConstants.WsSecurity10Namespace)
        //    {
        //        var id = first.GetAttribute("URI")?.Substring(1);
        //        var token = store.GetSecurityToken(id);
        //        if (token == null)
        //            throw context.CreateFailedCheckFault();
        //        return token.SecurityKey?.CryptoProviderFactory.;
        //    }

        //    return null;
        //}

        private async ValueTask<VerifyTokenResult> VerifyTokenAsync(XmlReader reader, SoapContext soap)
        {
            using var activity = Tracing.WsSecurity.Base.StartActivity($"{nameof(WsSecurityAuthenticationHandler)}.{nameof(VerifyTokenAsync)}");
            WsSecurityLogMessages.LogSecurityTokenElement(Logger, ref reader);
            foreach(var handler in _securityTokenHandlerProvider.GetAllSecurityTokenHandlers())
            {
                if (!handler.CanValidateToken) continue;
                if (!await CanReadTokenAsync(handler, reader)) continue;

                WsSecurityLogMessages.LogSecurityTokenHandlerValidationAttempt(Logger, handler);

                var parameters = await _tokenValidationParametersFactory.CreateAsync();
                var user = null as ClaimsPrincipal;
                var securityToken = null as SecurityToken;
                var token = null as string;
                
                try
                {
                    if (handler is IAsyncSecurityTokenHandler asyncHandler)
                    {
                        var result = await asyncHandler.ValidateTokenAsync(reader, parameters);
                        if (!result.Success)
                            throw result.Error;
                        user = result.User;
                        securityToken = result.Token;
                    }
                    else
                    {
                        user = handler.ValidateToken(reader, parameters, out securityToken);
                    }
                }
                catch (Exception ex)
                {
                    WsSecurityLogMessages.LogFailedSecurityTokenHandlerValidation(Logger, handler, ex);
                    continue;
                }
                
                if(user != null && securityToken != null)
                {
                    WsSecurityLogMessages.LogSuccessfulSecurityTokenHandlerValidation(Logger, handler);
                    return new VerifyTokenResult(user, securityToken);
                }
            }
            throw soap.CreateInvalidSecurityTokenFault();
        }

        private ValueTask<bool> CanReadTokenAsync(SecurityTokenHandler handler, XmlReader reader)
        {
            if (handler is IAsyncSecurityTokenHandler asyncHandler)
                return asyncHandler.CanReadTokenAsync(reader);
            return new ValueTask<bool>(handler.CanReadToken(reader));
        }

        private void HandleTimestamp(XmlReader reader, SoapContext soap)
        {
            var timestamp = ReadTimestamp(reader);
            AssertTimestamp(timestamp, soap);
            soap.SetWsSecurityTimestamp(timestamp);
        }

        private Timestamp ReadTimestamp(XmlReader reader)
        {
            WsSecurityLogMessages.LogTimestampElement(Logger, ref reader);

            var timestamp = new Timestamp
            {
                Id = reader.GetAttribute("Id", WsUtilityConstants.WsUtility10.Namespace)
            };

            reader.ReadToDescendant("Created", WsUtilityConstants.WsUtility10.Namespace);
            timestamp.Created = reader.ReadElementContentAsDateTime();
            while (!reader.EOF && !reader.IsStartElement("Expires", WsUtilityConstants.WsUtility10.Namespace))
                reader.Read();
            timestamp.Expires = reader.ReadElementContentAsDateTime();
            return timestamp;
        }

        private void AssertTimestamp(Timestamp timestamp, SoapContext context)
        {
            // TODO: add clock skew options
            var now = Clock.UtcNow.UtcDateTime;
            if (timestamp.Created.AddMinutes(-5).ToUniversalTime() > now || timestamp.Expires.ToUniversalTime() < now)
                throw context.CreateMessageExpiredFault();
        }
    }

    internal struct VerifyTokenResult
    {
        public ClaimsPrincipal User;
        public SecurityToken SecurityToken;
        //public string Token;

        public VerifyTokenResult(ClaimsPrincipal user, SecurityToken securityToken)
        {
            User = user;
            SecurityToken = securityToken;
        }

        public override bool Equals(object obj)
        {
            return obj is VerifyTokenResult other &&
                   //EqualityComparer<string>.Default.Equals(Token, other.Token) &&
                   EqualityComparer<ClaimsPrincipal>.Default.Equals(User, other.User) &&
                   EqualityComparer<SecurityToken>.Default.Equals(SecurityToken, other.SecurityToken);
        }

        public override int GetHashCode()
        {
            int hashCode = -920644486;
            hashCode = hashCode * -1521134295 + EqualityComparer<ClaimsPrincipal>.Default.GetHashCode(User);
            //hashCode = hashCode * -1521134295 + EqualityComparer<ClaimsPrincipal>.Default.GetHashCode(Token);
            hashCode = hashCode * -1521134295 + EqualityComparer<SecurityToken>.Default.GetHashCode(SecurityToken);
            return hashCode;
        }
    }
}
