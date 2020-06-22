using Solid.Identity.Tokens.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Logging
{
    internal class SecurityTokenElementLogMessageState : LogMessageState
    {
        public string Name { get; set; }
        public string Namespace { get; set; }
    }
}
