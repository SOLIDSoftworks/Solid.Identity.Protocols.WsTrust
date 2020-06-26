using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Xml
{
    class WsSecurityKeyInfo : KeyInfo
    {
        public WsSecurityTokenReference SecurityTokenReference { get; set; }
    }
}
