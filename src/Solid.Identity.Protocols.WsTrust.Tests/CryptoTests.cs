//using Microsoft.Extensions.DependencyInjection;
//using Microsoft.IdentityModel.Tokens;
//using Solid.Identity.Protocols.WsSecurity.Tokens;
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Security.Cryptography;
//using System.Security.Cryptography.X509Certificates;
//using System.Text;
//using System.Threading.Tasks;
//using Xunit;

//namespace Solid.Identity.Protocols.WsTrust.Tests
//{
//    public class CryptoTests
//    {
//        private CryptoProviderFactory _factory;

//        public CryptoTests()
//        {
//            var services = new ServiceCollection()
//                .AddLogging()
//                .BuildServiceProvider()
//            ;
//            var options = new WsTrustOptions()
//                .AddRsaSha1Support()
//                .AddSha1Support()
//                .AddHmacSha1Support()
//            ;
//            CryptoProviderFactory.Default.CustomCryptoProvider = new CustomCryptoProvider(options, services);
//            _factory = CryptoProviderFactory.Default;
//        }

//        [Theory]
//        [InlineData("http://www.w3.org/2000/09/xmldsig#sha1")]
//        [InlineData("SHA1")]
//        public void ShouldGetHashAlgorithm(string algorithm)
//        {
//            Assert.True(_factory.IsSupportedAlgorithm(algorithm));
//            // throw exception if it can't create
//            _ = _factory.CreateHashAlgorithm(algorithm);
//        }

//        [Theory]
//        [InlineData("http://www.w3.org/2000/09/xmldsig#rsa-sha1")]
//        [InlineData("RS1")]
//        public void ShouldGetAsymmetricSignatureProvider(string algorithm)
//        {
//            var certificate = new X509Certificate2(Convert.FromBase64String(Certificates.SigningCertificteBase64));
//            var key = new X509SecurityKey(certificate);

//            Assert.True(_factory.IsSupportedAlgorithm(algorithm));
//            // throw exception if it can't create
//            _ = _factory.CreateForSigning(key, algorithm);
//            _ = _factory.CreateForVerifying(key, algorithm);
//        }

//        [Theory]
//        [InlineData("http://www.w3.org/2000/09/xmldsig#hmac-sha1")]
//        [InlineData("H1")]
//        public void ShouldGetSymmetricSignatureProvider(string algorithm)
//        {
//            var bytes = new byte[16];
//            var random = RandomNumberGenerator.Create();
//            random.GetNonZeroBytes(bytes);
//            var key = new SymmetricSecurityKey(bytes);

//            Assert.True(_factory.IsSupportedAlgorithm(algorithm));
//            // throw exception if it can't create
//            _ = _factory.CreateForSigning(key, algorithm);
//            _ = _factory.CreateForVerifying(key, algorithm);
//        }

//        [Theory]
//        [InlineData("http://www.w3.org/2000/09/xmldsig#hmac-sha1")]
//        [InlineData("H1")]
//        public void ShouldGetKeyedHashAlgorithm(string algorithm)
//        {
//            var bytes = new byte[16];
//            var random = RandomNumberGenerator.Create();
//            random.GetNonZeroBytes(bytes);

//            Assert.True(_factory.IsSupportedAlgorithm(algorithm));
//            // throw exception if it can't create
//            _ = _factory.CreateKeyedHashAlgorithm(bytes, algorithm);
//        }
//    }
//}
