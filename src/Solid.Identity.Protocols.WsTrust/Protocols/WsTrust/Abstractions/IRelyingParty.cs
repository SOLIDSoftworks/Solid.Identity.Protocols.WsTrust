using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface IRelyingParty
    {
        string Id { get; }
        Uri AppliesTo { get; }
        Uri ReplyTo { get; }
        SecurityKey SigningKey { get; }
        SecurityAlgorithm SigningAlgorithm { get; }
        SecurityKey EncryptingKey { get; }
        SecurityAlgorithm EncryptingAlgorithm { get; }
        string Name { get; }
        int TokenLifeTime { get; }
        string TokenType { get; }
        bool Enabled { get; }
        IEnumerable<string> RequiredClaims { get; }
        IEnumerable<string> OptionalClaims { get; }
    }
}
