using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace Solid.Identity.Protocols.WsTrust
{
    public class RequestedSecurityTokenDescriptor : SecurityTokenDescriptor
    {
        public SecurityToken Token { get; set; }
        public SecurityTokenReference AttachedReference { get; set; }
        public SecurityTokenReference UnattachedReference { get; set; }
        public string TokenType { get; set; }
        public XmlElement TokenElement { get; set; }

        public virtual void ApplyTo(RequestSecurityTokenResponse response)
        {
            if (TokenType != null)
                response.TokenType = TokenType;

            if (TokenElement != null)
                response.RequestedSecurityToken = new RequestedSecurityToken(TokenElement);
            else if (Token != null)
                response.RequestedSecurityToken = new RequestedSecurityToken(Token);

            if (AttachedReference != null)
                response.AttachedReference = AttachedReference;

            if (UnattachedReference != null)
                response.UnattachedReference = UnattachedReference;

            if (IssuedAt != null && Expires != null)
                response.Lifetime = new Lifetime(IssuedAt, Expires);

            // no proof descriptor
            //if (proofDescriptor != null)
            //    proofDescriptor.ApplyTo(response);
        }
    }
}
