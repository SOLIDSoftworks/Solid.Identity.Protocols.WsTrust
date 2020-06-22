using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace Solid.Identity.Tokens
{
    public static class AuthenticationInstantClaim
    {
        public static Claim Now => new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddTHH:mm:ss.fffZ"), ClaimValueTypes.DateTime);
    }
}
