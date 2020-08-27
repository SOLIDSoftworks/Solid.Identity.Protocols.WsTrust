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
        string AppliesTo { get; }
        string ReplyTo { get; }
        SecurityKey SigningKey { get; }
        SecurityAlgorithm SigningAlgorithm { get; }
        SecurityKey EncryptingKey { get; }
        SecurityAlgorithm EncryptingAlgorithm { get; }
        string Name { get; }
        TimeSpan TokenLifeTime { get; }
        string TokenType { get; }
        bool Enabled { get; }
        IEnumerable<string> RequiredClaims { get; }
        IEnumerable<string> OptionalClaims { get; }
        Func<IServiceProvider, ClaimsPrincipal, ValueTask<bool>> AuthorizeAsync { get; }
    }
}
