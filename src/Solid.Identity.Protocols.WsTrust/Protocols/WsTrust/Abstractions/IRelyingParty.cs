using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Tokens;
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
        SigningAlgorithm SigningAlgorithm { get; }
        SecurityKey EncryptingKey { get; }
        EncryptionAlgorithm EncryptingAlgorithm { get; }
        bool RequiresEncryptedToken { get; }
        string Name { get; }
        TimeSpan TokenLifeTime { get; }
        string DefaultTokenType { get; }
        bool Enabled { get; }
        IEnumerable<string> RequiredClaims { get; }
        IEnumerable<string> OptionalClaims { get; }
        Func<IServiceProvider, ClaimsPrincipal, ValueTask<bool>> AuthorizeAsync { get; }
    }
}
