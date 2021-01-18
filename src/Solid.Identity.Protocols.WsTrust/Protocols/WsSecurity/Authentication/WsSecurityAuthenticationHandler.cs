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
            var soap = _soapContextAccessor.SoapContext;
            if (soap == null) return AuthenticateResult.NoResult();

            var index = soap.Request.Headers.FindHeader("Security", WsSecurityConstants.WsSecurity10.Namespace);
            if (index < 0) return AuthenticateResult.NoResult();

            try
            {
                var results = new List<(ClaimsPrincipal User, SecurityToken Token)>();

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
                            .Select(r => r.Token)
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
                properties.Parameters.Add(nameof(SecurityToken), result.Token);

                AddIssuerClaim(result.User, result.Token);

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
            WsSecurityLogMessages.LogSignatureElement(Logger, ref reader);

            var buffer = soap.Request.CreateBufferedCopy((int)(soap.HttpContext.Request.ContentLength ?? 64 * 1024));
            var message = buffer.CreateMessage();
            using(var stream = new MemoryStream())
            {
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

        }

        //private void AssertTimestamp(Timestamp timestamp)
        //{
        //    throw new NotImplementedException();
        //}

        //private Timestamp ReadTimestamp(EnvelopedSignatureReader reader)
        //{
        //    var timestamp = new Timestamp();
        //    timestamp.Id = reader.GetAttribute("Id", WsUtilityConstants.WsUtility10.Namespace);
        //    reader.ReadToDescendant("Created", WsUtilityConstants.WsUtility10.Namespace);
        //    timestamp.Created = reader.ReadElementContentAsDateTime();
        //    reader.ReadToFollowing("Expires", WsUtilityConstants.WsUtility10.Namespace);
        //    timestamp.Expires = reader.ReadElementContentAsDateTime();

        //    reader.MoveToElement();
        //    return timestamp;
        //}

        private void ValidateSignatures(SoapContext context, IEnumerable<SecurityToken> tokens)
        {
            var buffer = context.Request.CreateBufferedCopy((int)(context.HttpContext.Request.ContentLength ?? 64 * 1024));
            var request = buffer.CreateMessage();
            context.Request = buffer.CreateMessage();

            using (var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { CloseOutput = false }))
                    request.WriteMessage(writer);

                stream.Position = 0;

                using (var reader = new EnvelopedSignatureReader(XmlReader.Create(stream)))
                    _ = reader.ReadOuterXml();
            }
        }

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

        private async ValueTask<(ClaimsPrincipal User, SecurityToken Token)> VerifyTokenAsync(XmlReader reader, SoapContext soap)
        {
            WsSecurityLogMessages.LogSecurityTokenElement(Logger, ref reader);
            foreach(var handler in _securityTokenHandlerProvider.GetAllSecurityTokenHandlers())
            {
                if (!handler.CanValidateToken) continue;
                if (!await CanReadTokenAsync(handler, reader)) continue;

                WsSecurityLogMessages.LogSecurityTokenHandlerValidationAttempt(Logger, handler);

                var parameters = await _tokenValidationParametersFactory.CreateAsync();
                var user = null as ClaimsPrincipal;
                var token = null as SecurityToken;

                try
                {
                    if (handler is IAsyncSecurityTokenHandler asyncHandler)
                    {
                        var result = await asyncHandler.ValidateTokenAsync(reader, parameters);
                        if (!result.Success)
                            throw result.Error;
                        user = result.User;
                        token = result.Token;
                    }
                    else
                    {
                        user = handler.ValidateToken(reader, parameters, out token);
                    }
                }
                catch (Exception ex)
                {
                    WsSecurityLogMessages.LogFailedSecurityTokenHandlerValidation(Logger, handler, ex);
                    continue;
                }
                
                if(user != null && token != null)
                {
                    WsSecurityLogMessages.LogSuccessfulSecurityTokenHandlerValidation(Logger, handler);
                    return (user, token);
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

        //private async ValueTask<IEnumerable<(ClaimsPrincipal User, SecurityToken Token)>> VerifyTokensAsync(XDocument document, SoapContext soap)
        //{
        //    var elements = document.Root.Elements().Where(e => e.Name != Timestamp && e.Name != Signature);
        //    var users = new List<(ClaimsPrincipal User, SecurityToken Token)>();
        //    foreach (var element in elements)
        //    {
        //        //WsSecurityLogMessages.LogSecurityTokenElement(Logger, element);
        //        // using (var reader = element.CreateReader())
        //        // The preceding code doesn't work for SamlSecurityTokenHandler.
        //        // The following hack is extremely shaky. We're assuming that all signed SAML tokens are arriving unformatted. 
        //        // Let's hope Microsoft accepts our PR.
        //        // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/1437
        //        var xml = element.ToString(SaveOptions.DisableFormatting);
        //        using (var reader = XmlReader.Create(new MemoryStream(Encoding.UTF8.GetBytes(xml))))
        //        {
        //            reader.MoveToContent();
        //            var handled = false;
        //            foreach (var handler in _securityTokenHandlerProvider.GetAllSecurityTokenHandlers())
        //            {
        //                if (!handler.CanValidateToken) continue;

        //                var parameters = _tokenValidationParametersFactory.Create();

        //                if (handler is IAsyncSecurityTokenHandler asyncHandler && await asyncHandler.CanReadTokenAsync(reader))
        //                {
        //                    WsSecurityLogMessages.LogSecurityTokenHandlerValidationAttempt(Logger, handler);

        //                    try
        //                    {
        //                        var result = await asyncHandler.ValidateTokenAsync(reader, parameters);
        //                        if (!result.Success)
        //                            throw result.Error;
        //                        users.Add((result.User, result.Token));
        //                        WsSecurityLogMessages.LogSuccessfulSecurityTokenHandlerValidation(Logger, handler);
        //                        handled = true;
        //                        break;
        //                    }
        //                    catch (Exception ex)
        //                    {
        //                        WsSecurityLogMessages.LogFailedSecurityTokenHandlerValidation(Logger, handler, ex);
        //                        continue;
        //                    }
        //                }
        //                else if (handler.CanReadToken(reader))
        //                {
        //                    WsSecurityLogMessages.LogSecurityTokenHandlerValidationAttempt(Logger, handler);
        //                    try
        //                    {
        //                        var principal = handler.ValidateToken(reader, parameters, out var token);
        //                        if (token != null && principal != null)
        //                        {
        //                            users.Add((principal, token));
        //                            WsSecurityLogMessages.LogSuccessfulSecurityTokenHandlerValidation(Logger, handler);
        //                            handled = true;
        //                            break;
        //                        }
        //                    }
        //                    catch (Exception ex)
        //                    {
        //                        WsSecurityLogMessages.LogFailedSecurityTokenHandlerValidation(Logger, handler, ex);
        //                        continue;
        //                    }
        //                }
        //            }
        //            if (!handled)
        //                throw soap.CreateInvalidSecurityTokenFault();
        //        }
        //    }
        //    return users;
        //}

        //private void HandleTimestamp(XDocument document, SoapContext context)
        //{
        //    var element = document.Root.Element(Timestamp);
        //    WsSecurityLogMessages.LogTimestampElement(Logger, element);
        //    var timestamp = ReadTimestamp(element);
        //    AssertTimestamp(timestamp, context);
        //    context.SetWsSecurityTimestamp(timestamp);
        //}

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

        //private Timestamp ReadTimestamp(XElement element)
        //{
        //    var created = element.Element(XName.Get("Created", WsUtilityConstants.WsUtility10.Namespace));
        //    var expires = element.Element(XName.Get("Expires", WsUtilityConstants.WsUtility10.Namespace));
        //    var timestamp = new Timestamp
        //    {
        //        Id = element.Attributes().FirstOrDefault(a => a.Name == XName.Get("Id", WsUtilityConstants.WsUtility10.Namespace))?.Value,
        //        Created = DateTime.Parse(created.Value),
        //        Expires = DateTime.Parse(expires.Value)
        //    };
        //    return timestamp;
        //}

        private void AssertTimestamp(Timestamp timestamp, SoapContext context)
        {
            // TODO: add clock skew options
            var now = Clock.UtcNow.UtcDateTime;
            if (timestamp.Created.AddMinutes(-5).ToUniversalTime() > now || timestamp.Expires.ToUniversalTime() < now)
                throw context.CreateMessageExpiredFault();
        }
    }
}
