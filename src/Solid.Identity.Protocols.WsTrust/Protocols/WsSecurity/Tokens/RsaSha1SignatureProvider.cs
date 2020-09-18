using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class RsaSha1SignatureProvider : SignatureProvider
    {
        private readonly ILogger<RsaSha1SignatureProvider> _logger;
        private X509Certificate2 _certificate;

        public RsaSha1SignatureProvider(SecurityKey key, string algorithm, ILogger<RsaSha1SignatureProvider> logger)
            : base(key, algorithm)
        {
            if (!(key is X509SecurityKey x509))
                throw new ArgumentException("Only X509 security keys are supported.", nameof(key));
            _certificate = x509.Certificate;
            _logger = logger;
        }

        public override byte[] Sign(byte[] input)
        {
            if (!_certificate.HasPrivateKey) throw new InvalidOperationException("Cannot sign without private key.");
            _logger.LogDebug($"Signing with SHA1 using {_certificate.Subject}");
            using (var rsa = new RSACryptoServiceProvider())
            {
                var privateKey = _certificate.GetRSAPrivateKey();
                rsa.ImportParameters(privateKey.ExportParameters(true));
                return rsa.SignData(input, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            }
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            _logger.LogDebug($"Validating SHA1 using {_certificate.Subject}");
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
