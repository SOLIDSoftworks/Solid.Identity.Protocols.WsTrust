using Solid.Identity.Tokens.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Logging
{
    internal class UnableToGetAllClaims : LogMessageState
    {
        public IEnumerable<string> UnpopulatedClaimTypes { get; set; }
    }
}
