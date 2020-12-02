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
        ICollection<SecurityKey> SecurityKeys { get;}
        bool RestrictRelyingParties { get; }
        ICollection<string> AllowedRelyingParties { get; }
        bool Enabled { get; }
        ICollection<string> ValidEmbeddedCertificateSubjectNames { get; }
    }
}
