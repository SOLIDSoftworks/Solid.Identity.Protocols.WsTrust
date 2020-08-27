using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    public class IdentityProvider : IIdentityProvider
    {
        internal IdentityProvider() { }
        public IdentityProvider(string id) => Id = id;
        public string Id { get; internal set; }

        public string Name { get; set; }

        public bool RestrictRelyingParties { get; set; } = true;

        public IList<string> AllowedRelyingParties { get; set; } = new List<string>();

        public bool Enabled { get; set; } = true;

        public SecurityKey SecurityKey { get; set; }
    }
}
