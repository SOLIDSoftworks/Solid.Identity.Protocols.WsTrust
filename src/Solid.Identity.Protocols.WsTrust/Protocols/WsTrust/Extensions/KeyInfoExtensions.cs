using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.IdentityModel.Xml
{
    internal static class KeyInfoExtensions
    {
        public static IEnumerable<SecurityKey> GetSecurityKeys(this KeyInfo keys)
        {
            if (keys.RSAKeyValue != null)
            {
                var rsa = RSA.Create();
                var parameters = new RSAParameters
                {
                    Modulus = Convert.FromBase64String(keys.RSAKeyValue.Modulus),
                    Exponent = Convert.FromBase64String(keys.RSAKeyValue.Exponent)
                };
                rsa.ImportParameters(parameters);
                yield return new RsaSecurityKey(rsa);
            }

            if (keys.X509Data != null)
            {
                foreach (var x509 in keys.X509Data.SelectMany(x => x.Certificates).Select(c => new X509Certificate2(Convert.FromBase64String(c))))
                    yield return new X509SecurityKey(x509);
            }
        }
    }
}
