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
        public SecurityTokenHandler Inner { get; }

        public SecurityTokenHandlerWrapper(SecurityTokenHandler inner) => Inner = inner;

        public override Type TokenType => Inner.TokenType;

        public override int MaximumTokenSizeInBytes { get => Inner.MaximumTokenSizeInBytes; set => Inner.MaximumTokenSizeInBytes = value; }

        public override bool CanValidateToken => Inner.CanValidateToken;

        public override bool CanWriteToken => Inner.CanWriteToken;

        public override bool CanReadToken(XmlReader reader) => Inner.CanReadToken(reader);

        public override bool CanReadToken(string tokenString) => Inner.CanReadToken(tokenString);
        
        //public override bool CanWriteSecurityToken(SecurityToken securityToken)
        //{
        //    if (Inner.CanWriteSecurityToken(securityToken)) return true;
        //    return base.CanWriteSecurityToken(securityToken);
        //}

        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            try
            {
                return Inner.CreateSecurityTokenReference(token, attached);
            }
            catch
            {
                return null;
            }
        }

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor) => Inner.CreateToken(tokenDescriptor);

        public override bool Equals(object obj)
        {
            if (obj is SecurityTokenHandlerWrapper wrapper)
                return Inner.Equals(wrapper.Inner);
            return Inner.Equals(obj);
        }

        public override int GetHashCode() => Inner.GetHashCode();

        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters) => Inner.ReadToken(reader, validationParameters);

        public override SecurityToken ReadToken(string tokenString) => Inner.ReadToken(tokenString);

        public override SecurityToken ReadToken(XmlReader reader) => Inner.ReadToken(reader);

        public override string ToString() => Inner.ToString();

        //public override bool TryWriteSourceData(XmlWriter writer, SecurityToken securityToken) => Inner.TryWriteSourceData(writer, securityToken);

        public override ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken) => Inner.ValidateToken(securityToken, validationParameters, out validatedToken);

        public override ClaimsPrincipal ValidateToken(XmlReader reader, TokenValidationParameters validationParameters, out SecurityToken validatedToken) => Inner.ValidateToken(reader, validationParameters, out validatedToken);

        public override void WriteToken(XmlWriter writer, SecurityToken token) => Inner.WriteToken(writer, token);

        public override string WriteToken(SecurityToken token) => Inner.WriteToken(token);
    }
}
