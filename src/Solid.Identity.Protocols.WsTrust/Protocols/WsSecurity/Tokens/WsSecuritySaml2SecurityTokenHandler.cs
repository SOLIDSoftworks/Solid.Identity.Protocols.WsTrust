using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;

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
    }
}
