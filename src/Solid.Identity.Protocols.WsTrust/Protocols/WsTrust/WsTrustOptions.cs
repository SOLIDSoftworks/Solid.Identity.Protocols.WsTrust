using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Solid.Identity.Tokens;
using Solid.Identity.Protocols.WsSecurity.Tokens;

namespace Solid.Identity.Protocols.WsTrust
{
    public class WsTrustOptions
    {
        public string Issuer { get; set; }
        public SecurityKey DefaultSigningKey { get; set; }
        public SecurityAlgorithm DefaultSigningAlgorithm { get; set; } = SecurityAlgorithm.Asymmetric.RsaSha256;
        public EncryptingCredentials DefaultEncryptingCredentials { get; set; }
        public TimeSpan DefaultTokenLifetime { get; set; } = WsTrustDefaults.DefaultTokenLifetime;
        public int DefaultSymmetricKeySizeInBits { get; set; } = WsTrustDefaults.DefaultSymmetricKeySizeInBits;
        public int DefaultMaxSymmetricKeySizeInBits { get; set; } = WsTrustDefaults.DefaultMaxSymmetricKeySizeInBits;
        public string DefaultTokenType { get; set; } = WsTrustDefaults.DefaultTokenType;
        public TimeSpan MaxClockSkew { get; set; } = WsTrustDefaults.MaxClockSkew;
        public TimeSpan MaxTokenLifetime { get; set; } = WsTrustDefaults.MaxTokenLifetime;
        public bool ValidateTopLevelSignatures { get; set; } = true;
        internal List<SecurityTokenHandlerDescriptor> SecurityTokenHandlers { get; set; } = WsTrustDefaults.SecurityTokenHandlers;
    }
}
