using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class X509SecurityTokenHandler : AsyncSecurityTokenHandler
    {
        private ILogger<X509SecurityTokenHandler> _logger;
        private IX509Validator _validator;

        public X509SecurityTokenHandler(ILogger<X509SecurityTokenHandler> logger, IX509Validator validator = null)
        {
            _logger = logger;
            _validator = validator;
        }
        public override Type TokenType => typeof(X509SecurityToken);

        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters) => ReadToken(reader);

        public override void WriteToken(XmlWriter writer, SecurityToken token)
            => throw new NotSupportedException();

        public override string WriteToken(SecurityToken token)
            => throw new NotSupportedException();

        public override bool CanValidateToken => _validator != null;
        public override bool CanWriteToken => false;

        public override ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
            => throw new NotSupportedException("Synchronous validation not supported.");

        public override bool CanReadToken(string tokenString)
        {
            try
            {
                using (var reader = CreateReader(tokenString))
                    return CanReadToken(reader);
            }
            catch
            {
                return false;
            }
        }

        public override bool CanReadToken(XmlReader reader)
            => reader?.IsStartElement("BinarySecurityToken", WsSecurityConstants.WsSecurity10.Namespace) == true
            && reader.GetAttribute("ValueType") == "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
            && reader.GetAttribute("EncodingType") == "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        ;

        public override SecurityToken ReadToken(string tokenString) => ReadX509Certificate2Token(tokenString);
        public override SecurityToken ReadToken(XmlReader reader) => ReadX509Certificate2Token(reader);

        public X509SecurityToken ReadX509Certificate2Token(string tokenString)
        {
            using (var reader = CreateReader(tokenString))
                return ReadX509Certificate2Token(reader);
        }

        public X509SecurityToken ReadX509Certificate2Token(XmlReader reader)
        {
            if (!CanReadToken(reader))
                throw new Exception("Token read exception");

            var id = reader.GetAttribute("Id", WsUtilityConstants.WsUtility10.Namespace);
            var base64 = reader.ReadElementContentAsString();
            var bytes = Convert.FromBase64String(base64);
            var certificate = new X509Certificate2(bytes);

            return new X509SecurityToken(id, certificate);
        }

        public override ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(string securityToken, TokenValidationParameters validationParameters)
        {
            using (var reader = CreateReader(securityToken))
                return ValidateTokenAsync(CreateReader(securityToken), validationParameters);
        }

        public override async ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(XmlReader securityToken, TokenValidationParameters validationParameters)
        {
            if (!CanValidateToken) return null;
            var token = ReadX509Certificate2Token(securityToken);
            try
            {
                var user = await _validator.ValidateCertificateAsync(token.Certificate);
                if (user == null) throw new SecurityException("Could not validate certificate.");
                return new SecurityTokenValidationResult { Token = token, User = user, Success = true };
            }
            catch (Exception ex)
            {
                return new SecurityTokenValidationResult { Error = ex };
            }
        }

        private XmlDictionaryReader CreateReader(string tokenString)
        {
            if (string.IsNullOrWhiteSpace(tokenString) || tokenString.Length > MaximumTokenSizeInBytes)
                throw new Exception("Token read exception");

            var reader = new StringReader(tokenString);
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
            return XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(reader, settings));
        }
    }
}
