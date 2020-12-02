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
        ICollection<X509Name> ValidEmbeddedCertificateSubjectNames { get; }
        ICollection<X509Name> ValidEmbeddedCertificateIssuerNames { get; }

        // TODO: add flag which sets whether root certificate trust is required
    }
}
