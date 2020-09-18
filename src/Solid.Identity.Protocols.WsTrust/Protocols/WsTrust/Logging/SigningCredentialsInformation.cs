using Solid.Identity.Tokens.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Logging
{
    internal class SigningCredentialsInformation : LogMessageState
    {
        public string SecurityKeyName { get; set; }
        public string SecurityKeyType { get; set; }
        public string Algorithm { get; set; }
        public string Digest { get; set; }
    }
}
