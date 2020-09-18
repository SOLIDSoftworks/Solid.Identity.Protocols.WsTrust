using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
    internal static class SigningCredentialsExtensions
    {
        public static byte[] Digest(this SigningCredentials credentials, byte[] data)
        {
            if (credentials == null) throw new ArgumentNullException(nameof(credentials));
            if (credentials.Digest == null) throw new InvalidOperationException("Unable to create digest from signing credentials");

            var factory = credentials.GetCryptoProviderFactory();
            if (!factory.IsSupportedAlgorithm(credentials.Digest))
                throw new NotSupportedException($"Digest algorithm not supported: {credentials.Algorithm}");
            using (var algorithm = factory.CreateHashAlgorithm(credentials.Digest))
            {
                var hash = algorithm.ComputeHash(data);
                return hash;
            }
        }

        public static string Digest(this SigningCredentials credentials, string data, Encoding dataEncoding = null)
        {
            if (dataEncoding == null) dataEncoding = Encoding.UTF8;
            var bytes = dataEncoding.GetBytes(data);
            var signed = credentials.Digest(bytes);
            return Convert.ToBase64String(signed);
        }

        public static byte[] Sign(this SigningCredentials credentials, byte[] data)
        {
            if (credentials == null) throw new ArgumentNullException(nameof(credentials));
            if (credentials.Algorithm == null) throw new InvalidOperationException("Unable to create signature from signing credentials");

            var factory = credentials.GetCryptoProviderFactory();
            if (!factory.IsSupportedAlgorithm(credentials.Algorithm, credentials.Key))
                throw new NotSupportedException($"Signing algorithm not supported: {credentials.Algorithm}");
            using (var algorithm = factory.CreateForSigning(credentials.Key, credentials.Algorithm, false))
            {
                var signed = algorithm.Sign(data);
                return signed;
            }
        }

        public static string Sign(this SigningCredentials credentials, string data, Encoding dataEncoding = null)
        {
            if (dataEncoding == null) dataEncoding = Encoding.UTF8;
            var bytes = dataEncoding.GetBytes(data);
            var signed = credentials.Sign(bytes);
            return Convert.ToBase64String(signed);
        }

        public static CryptoProviderFactory GetCryptoProviderFactory(this SigningCredentials credentials)
        {
            if (credentials == null) throw new ArgumentNullException(nameof(credentials));
            return credentials.CryptoProviderFactory ?? credentials.Key?.CryptoProviderFactory;
        }
    }
}
