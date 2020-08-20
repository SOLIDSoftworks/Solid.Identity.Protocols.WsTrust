using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    public static class WsTrustOptionsExtensions_Algorithms
    {
        public static WsTrustOptions AddSha1Support(this WsTrustOptions options)
            => options.AddSupportedHashAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1", _ => SHA1.Create());

        public static WsTrustOptions AddSha1WithRsaSupport(this WsTrustOptions options)
            => options.AddSupportedSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1", (services, key) =>
            {
                var logger = services.GetRequiredService<ILogger<RsaSha1SignatureProvider>>();
                return new RsaSha1SignatureProvider(key, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", logger);
            });
    }
}
