using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Solid.Identity.Tokens;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust.Abstractions;

namespace Solid.Identity.Protocols.WsTrust
{
    public class WsTrustOptions
    {
        public string Issuer { get; set; }
        public string DefaultAppliesTo { get; set; }
        public SecurityKey DefaultSigningKey { get; set; }
        public SecurityAlgorithm DefaultSigningAlgorithm { get; set; } = SecurityAlgorithm.Asymmetric.RsaSha256;
        public EncryptingCredentials DefaultEncryptingCredentials { get; set; }
        public TimeSpan DefaultTokenLifetime { get; set; } = WsTrustDefaults.DefaultTokenLifetime;
        public int DefaultSymmetricKeySizeInBits { get; set; } = WsTrustDefaults.DefaultSymmetricKeySizeInBits;
        public int DefaultMaxSymmetricKeySizeInBits { get; set; } = WsTrustDefaults.DefaultMaxSymmetricKeySizeInBits;
        public string DefaultTokenType { get; set; } = WsTrustDefaults.DefaultTokenType;
        public TimeSpan MaxClockSkew { get; set; } = WsTrustDefaults.MaxClockSkew;
        public TimeSpan MaxTokenLifetime { get; set; } = WsTrustDefaults.MaxTokenLifetime;
        public bool UseEmbeddedCertificatesForValidation { get; set; } = false;
        internal IDictionary<string, HashAlgorithmDescriptor> SupportedHashAlgorithms { get; } = new Dictionary<string, HashAlgorithmDescriptor>();
        internal IDictionary<string, SignatureProviderDescriptor> SupportedSignatureAlgorithms { get; } = new Dictionary<string, SignatureProviderDescriptor>();
        internal IDictionary<string, IRelyingParty> RelyingParties { get; } = new Dictionary<string, IRelyingParty>();
        // TODO: change this to Uri key?
        internal IDictionary<string, IIdentityProvider> IdentityProviders { get; } = new Dictionary<string, IIdentityProvider>();
        internal IList<SecurityTokenHandlerDescriptor> SecurityTokenHandlers { get; } = WsTrustDefaults.SecurityTokenHandlers;
    }
}
