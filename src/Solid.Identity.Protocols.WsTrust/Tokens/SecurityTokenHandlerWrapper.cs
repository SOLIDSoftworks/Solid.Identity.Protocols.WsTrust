using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Tokens
{
    internal class SecurityTokenHandlerWrapper : AsyncSecurityTokenHandler
    {
        private SecurityTokenHandler _inner;

        public SecurityTokenHandlerWrapper(SecurityTokenHandler inner) => _inner = inner;

        public override Type TokenType => _inner.TokenType;

        public override int MaximumTokenSizeInBytes { get => _inner.MaximumTokenSizeInBytes; set => _inner.MaximumTokenSizeInBytes = value; }

        public override bool CanValidateToken => _inner.CanValidateToken;

        public override bool CanWriteToken => _inner.CanWriteToken;

        public override bool CanReadToken(XmlReader reader) => _inner.CanReadToken(reader);

        public override bool CanReadToken(string tokenString) => _inner.CanReadToken(tokenString);
        
        public override bool CanWriteSecurityToken(SecurityToken securityToken)
        {
            if (_inner.CanWriteSecurityToken(securityToken)) return true;
            return base.CanWriteSecurityToken(securityToken);
        }

        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached) => _inner.CreateSecurityTokenReference(token, attached);

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor) => _inner.CreateToken(tokenDescriptor);

        public override bool Equals(object obj)
        {
            if (obj is SecurityTokenHandlerWrapper wrapper)
                return _inner.Equals(wrapper._inner);
            return _inner.Equals(obj);
        }

        public override int GetHashCode() => _inner.GetHashCode();

        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters) => _inner.ReadToken(reader, validationParameters);

        public override SecurityToken ReadToken(string tokenString) => _inner.ReadToken(tokenString);

        public override SecurityToken ReadToken(XmlReader reader) => _inner.ReadToken(reader);

        public override string ToString() => _inner.ToString();

        public override bool TryWriteSourceData(XmlWriter writer, SecurityToken securityToken) => _inner.TryWriteSourceData(writer, securityToken);

        public override ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken) => _inner.ValidateToken(securityToken, validationParameters, out validatedToken);

        public override ClaimsPrincipal ValidateToken(XmlReader reader, TokenValidationParameters validationParameters, out SecurityToken validatedToken) => _inner.ValidateToken(reader, validationParameters, out validatedToken);

        public override void WriteToken(XmlWriter writer, SecurityToken token) => _inner.WriteToken(writer, token);

        public override string WriteToken(SecurityToken token) => _inner.WriteToken(token);
    }    
}
