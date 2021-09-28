using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class WsSecuritySaml2SecurityKeyIdentifierClause : WsSecuritySecurityKeyIdentifierClause
    {
        private Saml2SecurityToken _token;

        public WsSecuritySaml2SecurityKeyIdentifierClause(Saml2SecurityToken token)
        {
            _token = token;
        }

        public override SecurityTokenReference CreateReference()
        {
            var keyIdentifier = new KeyIdentifier(_token.Id)
            {
                ValueType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID",
            };
            var reference = new SecurityTokenReference(keyIdentifier)
            {
                TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
            };
            return reference;
        }
    }
}
