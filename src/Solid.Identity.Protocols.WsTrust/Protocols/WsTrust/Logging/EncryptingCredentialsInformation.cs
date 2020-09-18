using Solid.Identity.Tokens.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Logging
{
    internal class EncryptingCredentialsInformation : LogMessageState
    {
        public string SecurityKeyName { get; set; }
        public string SecurityKeyType { get; set; }
        public string KeyWrapAlgorithm { get; set; }
        public string DataEncryptionAlgorithm { get; set; }
    }
}
