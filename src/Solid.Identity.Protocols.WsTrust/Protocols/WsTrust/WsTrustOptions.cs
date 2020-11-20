using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Solid.Identity.Tokens;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using System.Security.Cryptography;
using Solid.IdentityModel.Tokens;

namespace Solid.Identity.Protocols.WsTrust
{
    public class WsTrustOptions
    {
        public string Issuer { get; set; }
        public string Name { get; set; }
        public string DefaultAppliesTo { get; set; }
        public SecurityKey DefaultSigningKey { get; set; }
        public SignatureMethod DefaultSigningAlgorithm { get; set; } = SignatureMethod.RsaSha256;
        public SecurityKey DefaultEncryptionKey { get; set; }
        public EncryptionMethod DefaultEncryptionAlgorithm { get; set; } = EncryptionMethod.Aes128CbcWithRsaOaepKeyWrap;
        public TimeSpan DefaultTokenLifetime { get; set; } = WsTrustDefaults.DefaultTokenLifetime;
        public int DefaultSymmetricKeySizeInBits { get; set; } = WsTrustDefaults.DefaultSymmetricKeySizeInBits;
        public int DefaultMaxSymmetricKeySizeInBits { get; set; } = WsTrustDefaults.DefaultMaxSymmetricKeySizeInBits;
        public string DefaultTokenType { get; set; } = WsTrustDefaults.DefaultTokenType;
        public TimeSpan MaxClockSkew { get; set; } = WsTrustDefaults.MaxClockSkew;
        public TimeSpan MaxTokenLifetime { get; set; } = WsTrustDefaults.MaxTokenLifetime;
        public bool UseEmbeddedCertificatesForValidation { get; set; } = false;

        public WsTrustOptions AddRelyingParty(string appliesTo, Action<RelyingParty> configureRelyingParty)
        {
            var party = new RelyingParty { AppliesTo = appliesTo };
            configureRelyingParty(party);
            RelyingParties[appliesTo] = party;
            return this;
        }

        public WsTrustOptions AddIdentityProvider(string id, Action<IdentityProvider> configureIdentityProvider)
        {
            var idp = new IdentityProvider { Id = id };
            configureIdentityProvider(idp);
            IdentityProviders[id] = idp;
            return this;
        }

        public WsTrustOptions AddSecurityTokenHandler(SecurityTokenHandler handler, params string[] requestedTokenTypes)
            => AddSecurityTokenHandler(_ => handler, requestedTokenTypes);

        public WsTrustOptions AddSecurityTokenHandler(Func<IServiceProvider, SecurityTokenHandler> factory, params string[] requestedTokenTypes)
        {
            SecurityTokenHandlers.Add(new SecurityTokenHandlerDescriptor(requestedTokenTypes, factory));
            return this;
        }

        public WsTrustOptions AddSupportedHashAlgorithm(string algorithm, Func<IServiceProvider, HashAlgorithm> factory)
        {
            SupportedHashAlgorithms[algorithm] = new HashAlgorithmDescriptor(algorithm, (services, _) => factory(services));
            return this;
        }

        public WsTrustOptions AddSupportedSignatureAlgorithm(string algorithm, Func<IServiceProvider, SecurityKey, bool, SignatureProvider> factory)
        {
            SupportedSignatureAlgorithms[algorithm] = new SignatureProviderDescriptor(algorithm, (services, args) => factory(services, args[0] as SecurityKey, (bool)args[1]));
            return this;
        }

        public WsTrustOptions AddSupportedKeyWrapAlgorithm(string algorithm, Func<IServiceProvider, SecurityKey, bool, KeyWrapProvider> factory)
        {
            SupportedKeyWrapAlgorithms[algorithm] = new KeyWrapProviderDescriptor(algorithm, (services, args) => factory(services, args[0] as SecurityKey, (bool)args[1]));
            return this;
        }

        public WsTrustOptions AddSupportedKeyedHashAlgorithm(string algorithm, Func<IServiceProvider, byte[], KeyedHashAlgorithm> factory)
        {
            SupportedKeyedHashAlgorithms[algorithm] = new KeyedHashAlgorithmDescriptor(algorithm, (services, args) => factory(services, args[0] as byte[]));
            return this;
        }

        public WsTrustOptions AddSupportedEncryptionAlgorithm(string algorithm, Func<IServiceProvider, SecurityKey, AuthenticatedEncryptionProvider> factory)
        {
            SupportedEncryptionAlgorithms[algorithm] = new AuthenticatedEncryptionProviderDescriptor(algorithm, (services, args) => factory(services, args[0] as SecurityKey));
            return this;
        }

        internal IDictionary<string, HashAlgorithmDescriptor> SupportedHashAlgorithms { get; } = new Dictionary<string, HashAlgorithmDescriptor>();
        internal IDictionary<string, SignatureProviderDescriptor> SupportedSignatureAlgorithms { get; } = new Dictionary<string, SignatureProviderDescriptor>();
        internal IDictionary<string, KeyWrapProviderDescriptor> SupportedKeyWrapAlgorithms { get; } = new Dictionary<string, KeyWrapProviderDescriptor>();
        internal IDictionary<string, KeyedHashAlgorithmDescriptor> SupportedKeyedHashAlgorithms { get; } = new Dictionary<string, KeyedHashAlgorithmDescriptor>();
        internal IDictionary<string, AuthenticatedEncryptionProviderDescriptor> SupportedEncryptionAlgorithms { get; } = new Dictionary<string, AuthenticatedEncryptionProviderDescriptor>();
        internal IDictionary<string, IRelyingParty> RelyingParties { get; } = new Dictionary<string, IRelyingParty>();

        internal IDictionary<string, IIdentityProvider> IdentityProviders { get; } = new Dictionary<string, IIdentityProvider>();
        internal IList<SecurityTokenHandlerDescriptor> SecurityTokenHandlers { get; } = WsTrustDefaults.SecurityTokenHandlers;
    }
}
