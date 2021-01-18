using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WsTrustOptionsExtensions_Algorithms
    {
        public static WsTrustOptions AddSha1Support(this WsTrustOptions options)
            => options
                .AddSupportedHashAlgorithm("SHA1", _ => SHA1.Create())
                .AddSupportedHashAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1", _ => SHA1.Create())
            ;

        public static WsTrustOptions AddRsaSha1Support(this WsTrustOptions options)
            => options
                .AddSupportedSignatureAlgorithm("RS1", (services, key, _) =>
                {
                    var logger = services.GetRequiredService<ILogger<RsaSha1SignatureProvider>>();
                    return new RsaSha1SignatureProvider(key, "RS1", logger);
                })
                .AddSupportedSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1", (services, key, _) =>
                {
                    var logger = services.GetRequiredService<ILogger<RsaSha1SignatureProvider>>();
                    return new RsaSha1SignatureProvider(key, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", logger);
                })
            ;

        public static WsTrustOptions AddHmacSha1Support(this WsTrustOptions options)
            => options
                .AddSupportedKeyedHashAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1", (_, key) => new HMACSHA1(key))
                .AddSupportedKeyedHashAlgorithm("H1", (_, key) => new HMACSHA1(key))
                .AddSupportedSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1", (_, key, __) => new SymmetricSignatureProvider(key, "http://www.w3.org/2000/09/xmldsig#hmac-sha1"))
                .AddSupportedSignatureAlgorithm("H1", (_, key, __) => new SymmetricSignatureProvider(key, "H1"))
        ;
    }
}
