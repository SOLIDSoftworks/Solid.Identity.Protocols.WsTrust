using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Xml
{
    class WsSecurityTokenReference : SecurityTokenReference
    {
        public WsSecurityTokenReference(KeyIdentifier keyIdentifier) 
            : base(keyIdentifier)
        {
        }

        public Reference Reference { get; set; }
    }
}
