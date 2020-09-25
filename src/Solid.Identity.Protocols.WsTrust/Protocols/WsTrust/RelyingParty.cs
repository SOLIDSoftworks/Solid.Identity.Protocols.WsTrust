using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    public class RelyingParty : IRelyingParty
    {
        internal RelyingParty() { }
        public RelyingParty(string appliesTo) => AppliesTo = appliesTo;
        public string Id => AppliesTo ?? throw new ArgumentNullException(nameof(AppliesTo));
        public string AppliesTo { get; internal set; }
        public string ExpectedIssuer { get; set; }
        public string ReplyTo { get; set; }
        public SecurityKey SigningKey { get; set; }
        public SigningAlgorithm SigningAlgorithm { get; set; }
        public SecurityKey EncryptingKey { get; set; }
        public EncryptionAlgorithm EncryptingAlgorithm { get; set; }
        public bool RequiresEncryptedToken { get; set; } = false;
        public bool RequiresEncryptedSymmetricKeys { get; set; } = false;
        public string Name { get; set; }
        public TimeSpan? TokenLifeTime { get; set; }
        public TimeSpan? ClockSkew { get; set; }
        public string DefaultTokenType { get; set; }
        public bool Enabled { get; set; } = true;
        public ICollection<string> RequiredClaims { get; internal set; } = new List<string>();
        public ICollection<string> OptionalClaims { get; internal set; } = new List<string>();
        public Func<IServiceProvider, ClaimsPrincipal, ValueTask<bool>> AuthorizeAsync { get; set; } = (_, __) => new ValueTask<bool>(true);
        public bool ValidateRequestedTokenType { get; set; } = false;
        public ICollection<string> SupportedTokenTypes { get; internal set; } = new List<string>();
    }
}
