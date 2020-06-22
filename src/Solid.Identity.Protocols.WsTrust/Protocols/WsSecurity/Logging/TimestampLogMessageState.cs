using Solid.Identity.Protocols.WsSecurity.Xml;
using Solid.Identity.Tokens.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Logging
{
    internal class TimestampLogMessageState : LogMessageState
    {
        private Timestamp _timestamp;

        public TimestampLogMessageState(Timestamp timestamp) => _timestamp = timestamp;

        public string Id => _timestamp?.Id;

        public DateTime? Created => _timestamp?.Created;
               
        public DateTime? Expires => _timestamp?.Expires;
    }
}
