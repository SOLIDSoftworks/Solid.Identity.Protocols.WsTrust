using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    public class RelyingParty : IRelyingParty
    {
        public string Id => AppliesTo ?? throw new ArgumentNullException(nameof(AppliesTo));
        public string AppliesTo { get; internal set; }
        public string ReplyTo { get; set; }
        public SecurityKey SigningKey { get; set; }
        public SecurityAlgorithm SigningAlgorithm { get; set; }
        public SecurityKey EncryptingKey { get; set; }
        public SecurityAlgorithm EncryptingAlgorithm { get; set; }
        public string Name { get; set; }
        public int TokenLifeTime { get; set; }
        public string TokenType { get; set; }
        public bool Enabled { get; set; } = true;
        public IEnumerable<string> RequiredClaims { get; set; } = Enumerable.Empty<string>();
        public IEnumerable<string> OptionalClaims { get; set; } = Enumerable.Empty<string>();
    }
}
