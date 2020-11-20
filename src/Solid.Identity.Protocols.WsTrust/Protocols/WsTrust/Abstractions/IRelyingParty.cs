using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Tokens;
using Solid.IdentityModel.Tokens;
using Solid.IdentityModel.Tokens.Crypto;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface IRelyingParty
    {
        string Id { get; }
        string ExpectedIssuer { get; }
        string AppliesTo { get; }
        string ReplyTo { get; }
        SecurityKey SigningKey { get; }
        SignatureMethod SigningAlgorithm { get; }
        SecurityKey EncryptingKey { get; }
        EncryptionMethod EncryptingAlgorithm { get; }
        bool RequiresEncryptedToken { get; }
        bool RequiresEncryptedSymmetricKeys { get; }
        string Name { get; }
        TimeSpan? TokenLifeTime { get; }
        TimeSpan? ClockSkew { get; }
        string DefaultTokenType { get; }
        bool ValidateRequestedTokenType { get; }
        ICollection<string> SupportedTokenTypes { get; }
        bool Enabled { get; }
        ICollection<string> RequiredClaims { get; }
        ICollection<string> OptionalClaims { get; }
        Func<IServiceProvider, ClaimsPrincipal, ValueTask<bool>> AuthorizeAsync { get; }
    }
}
