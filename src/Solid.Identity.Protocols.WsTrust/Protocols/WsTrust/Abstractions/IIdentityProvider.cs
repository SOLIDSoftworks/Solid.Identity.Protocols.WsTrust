using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface IIdentityProvider
    {
        string Id { get; }
        string Name { get; }
        SecurityKey SecurityKey { get;}
        bool RestrictRelyingParties { get; }
        IList<string> AllowedRelyingParties { get; }
        bool Enabled { get; }
    }
}
