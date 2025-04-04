using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Tokens;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class UserNameSecurityTokenHandler : AsyncSecurityTokenHandler
    {
        private ISoapContextAccessor _soapContextAccessor;
        private ILogger<UserNameSecurityTokenHandler> _logger;
        private IPasswordValidator _validator;

        public UserNameSecurityTokenHandler(ISoapContextAccessor soapContextAccessor, ILogger<UserNameSecurityTokenHandler> logger, IPasswordValidator validator = null)
        {
            _soapContextAccessor = soapContextAccessor;
            _logger = logger;
            _validator = validator;
        }
        public override Type TokenType => typeof(UserNameSecurityToken);

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

        public override bool CanReadToken(XmlReader reader) => reader?.IsStartElement("UsernameToken", WsSecurityConstants.WsSecurity10.Namespace) == true;

        public override SecurityToken ReadToken(string tokenString) => ReadUsernameToken(tokenString);
        public override SecurityToken ReadToken(XmlReader reader) => ReadUsernameToken(reader);

        public UserNameSecurityToken ReadUsernameToken(string tokenString)
        {
            using (var reader = CreateReader(tokenString))
                return ReadUsernameToken(reader);
        }

        public UserNameSecurityToken ReadUsernameToken(XmlReader reader)
        {
            
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(UserNameSecurityTokenHandler)}.{nameof(ReadUsernameToken)}");
            if (!CanReadToken(reader))
                throw new Exception("Token read exception");

            var timestamp = _soapContextAccessor.SoapContext.GetWsSecurityTimestamp();

            var id = reader.GetAttribute("Id", WsUtilityConstants.WsUtility10.Namespace);
            var userName = "";
            var password = "";
            var type = "";
            if (reader.ReadToDescendant("Username", WsSecurityConstants.WsSecurity10.Namespace))
                userName = reader.ReadElementContentAsString();
            if (reader.IsStartElement("Password", WsSecurityConstants.WsSecurity10.Namespace))
            {
                type = reader.GetAttribute("Type", WsSecurityConstants.WsSecurity10.Namespace);
                password = reader.ReadElementContentAsString();
            }

            return new UserNameSecurityToken(id, timestamp.Created, timestamp.Expires, userName, password, type);
        }

        public override ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(string securityToken, TokenValidationParameters validationParameters)
        {
            using (var reader = CreateReader(securityToken))
                return ValidateTokenAsync(CreateReader(securityToken), validationParameters);
        }

        public override async ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(XmlReader securityToken, TokenValidationParameters validationParameters)
        {
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(UserNameSecurityTokenHandler)}.{nameof(ValidateTokenAsync)}");
            if (!CanValidateToken) return null;
            var token = ReadUsernameToken(securityToken);
            try
            {
                var user = await _validator.ValidatePasswordAsync(token.UserName, token.Password);
                if (user == null) throw new SecurityException("Could not validate userName and/or password.");
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
