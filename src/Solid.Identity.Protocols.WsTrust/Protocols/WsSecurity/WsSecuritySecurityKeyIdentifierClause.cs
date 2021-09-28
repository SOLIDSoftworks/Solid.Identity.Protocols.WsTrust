using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity
{
    public abstract class WsSecuritySecurityKeyIdentifierClause : SecurityKeyIdentifierClause
    {
        public abstract SecurityTokenReference CreateReference();
    }
}
