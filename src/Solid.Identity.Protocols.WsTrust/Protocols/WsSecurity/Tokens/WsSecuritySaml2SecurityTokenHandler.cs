using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    public class WsSecuritySaml2SecurityTokenHandler : Saml2EncryptedSecurityTokenHandler
    {
        public WsSecuritySaml2SecurityTokenHandler()
        {
        }

        public WsSecuritySaml2SecurityTokenHandler(IOptionsMonitor<Saml2Options> monitor) : base(monitor)
        {
        }

        public WsSecuritySaml2SecurityTokenHandler(ExtendedSaml2Serializer serializer, Saml2Options options) : base(serializer, options)
        {
        }

        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            if (!(token is Saml2SecurityToken saml2)) throw new ArgumentException($"Token must be a {nameof(Saml2SecurityToken)}.");
            return new WsSecuritySaml2SecurityKeyIdentifierClause(saml2);
        }

        public override ClaimsPrincipal ValidateToken(XmlReader reader, TokenValidationParameters validationParameters,
            out SecurityToken validatedToken)
        {
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(WsSecuritySaml2SecurityTokenHandler)}.{nameof(ValidateToken)}");
            return base.ValidateToken(reader, validationParameters, out validatedToken);
        }
        

        public override Saml2SecurityToken ReadSaml2Token(XmlReader reader)
        {
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(WsSecuritySaml2SecurityTokenHandler)}.{nameof(ReadSaml2Token)}");
            return base.ReadSaml2Token(reader);
        }

        public override Saml2SecurityToken ReadSaml2Token(XmlReader reader, TokenValidationParameters validationParameters)
        {
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(WsSecuritySaml2SecurityTokenHandler)}.{nameof(ReadSaml2Token)}");
            return base.ReadSaml2Token(reader, validationParameters);
        }

        public override void WriteEncryptedSecurityToken(XmlWriter writer, Saml2EncryptedSecurityToken securityToken)
        {
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(WsSecuritySaml2SecurityTokenHandler)}.{nameof(WriteEncryptedSecurityToken)}");
            base.WriteEncryptedSecurityToken(writer, securityToken);
        }

        public override void WriteToken(XmlWriter writer, SecurityToken securityToken)
        {
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(WsSecuritySaml2SecurityTokenHandler)}.{nameof(WriteToken)}");
            base.WriteToken(writer, securityToken);
        }

        public override string WriteToken(SecurityToken securityToken)
        {
            using var activity = Tracing.WsSecurity.Tokens.StartActivity($"{nameof(WsSecuritySaml2SecurityTokenHandler)}.{nameof(WriteToken)}");
            return base.WriteToken(securityToken);
        }
    }
}
