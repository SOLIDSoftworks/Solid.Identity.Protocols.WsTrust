using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsSecurity.Middleware;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class Solid_Identity_Protocols_WsTrust_ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseWsTrust13AsyncService(this IApplicationBuilder builder)
            => builder.UseWsTrust13AsyncService("/trust/13");


        public static IApplicationBuilder UseWsTrust13AsyncService(this IApplicationBuilder builder, PathString pathPrefix)
        {
            CryptoProviderFactory.Default.CustomCryptoProvider = new DSigCryptoProvider();

            builder.MapSoapService<IWsTrust13AsyncContract>(pathPrefix, app =>
            {
                app.UseMiddleware<WsSecurityMiddleware>();
            });
            return builder;
        }
    }

    internal class DSigCryptoProvider : ICryptoProvider
    {
        private static readonly IEnumerable<string> _supportedAlgorithms = new[]
        {
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#sha1"
        };

        public object Create(string algorithm, params object[] args)
        {
            if (algorithm == _supportedAlgorithms.First())
            {
                var key = args.OfType<X509SecurityKey>().FirstOrDefault();
                if (key == null)
                    throw new NotSupportedException();

                return new RsaSha1SignatureProvider(key, algorithm);
            }
            if(algorithm == _supportedAlgorithms.Last())
            {
                return SHA1.Create();
            }
            throw new NotSupportedException();
        }

        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
            => _supportedAlgorithms.Contains(algorithm);

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposable)
                disposable?.Dispose();
        }
    }

    internal class RsaSha1SignatureProvider : SignatureProvider
    {
        private X509Certificate2 _certificate;

        public RsaSha1SignatureProvider(X509SecurityKey key, string algorithm) 
            : base(key, algorithm)
        {
            _certificate = key.Certificate;
        }

        public override byte[] Sign(byte[] input)
        {
            if (!_certificate.HasPrivateKey) throw new InvalidOperationException("Cannot sign without private key.");
            using(var rsa = new RSACryptoServiceProvider())
            {
                var privateKey = _certificate.GetRSAPrivateKey();
                rsa.ImportParameters(privateKey.ExportParameters(true));
                return rsa.SignData(input, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            }
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var publicKey = _certificate.GetRSAPublicKey();
                rsa.ImportParameters(publicKey.ExportParameters(false));
                return rsa.VerifyData(input, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            }
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
