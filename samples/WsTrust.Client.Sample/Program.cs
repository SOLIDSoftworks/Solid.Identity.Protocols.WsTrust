using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.IdentityModel.Tokens;
using Solid.IdentityModel.Tokens.Xml;
using Solid.ServiceModel.Security;
using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel;
using System.Text.Json;
using System.Threading.Tasks;

namespace WsTrust.Client.Sample
{
    class Program
    {
        const int iterations = 1_000_000;

        static async Task Main(string[] args)
        {
            IdentityModelEventSource.ShowPII = true;

            await Task.Delay(5000);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, "username")
            };
            var identity = new ClaimsIdentity(claims, "Sample");
            var handler = new Saml2SecurityTokenHandler();

            var parameters = CreateRsaParameters();
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameters);

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "urn:sample.identityprovider",
                Audience = "urn:sample.issuer",
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow.AddMinutes(-5),
                Expires = DateTime.UtcNow.AddHours(2),
                Subject = identity,
                SigningCredentials = SignatureMethod.RsaSha256.CreateCredentials(new RsaSecurityKey(rsa))
            };
            var token = handler.CreateToken(descriptor);

            var binding = new WsTrustIssuedTokenBinding();
            var endpoint = new EndpointAddress("https://localhost:5001/trust/13");

            var factory = new WsTrustChannelFactory(binding, endpoint);
            factory.SecurityTokenHandlers.Add(handler);

            for (var i = 0; i < iterations; i++)
            {
                var channel = factory.CreateChannelWithIssuedToken(token);

                var request = new WsTrustRequest(WsTrustConstants.Trust13.WsTrustActions.Issue)
                {
                    KeyType = WsTrustKeyTypes.Trust13.Bearer,
                    AppliesTo = new AppliesTo(new EndpointReference("urn:sample:relyingparty"))
                };
                var response = await channel.IssueAsync(request);
                var requestedToken = response.GetRequestedSecurityToken() as GenericXmlSecurityToken;

                var assertion = requestedToken.Element.OuterXml;
                Console.WriteLine(assertion);
            }
            Console.ReadKey();
        }

        static RSAParameters CreateRsaParameters()
        {
            var d = "WblXjZ8W157UzsVrkFjg6rQglZWOPbyA5V1h1Hfzxlh2cpTEEGB8CmrjGIQ7Ya/Z6+r8csFUC83J/JiA9wOHJkl3kh8yxB461LQzbRW6FnOaDbDOXf9ZjJQwXZojsej5oKAW5j78GjxzpVJ9DCzNQ5PIxqOcaP7Y4x+tq7XsPJxp3PK9mIg7d62HA4/a7wZajc+oUOEdQUkp7hxkJxeAx2kdA9CgQHOaXeaxtm4/7ByJ+ZCjqKYW/qFx2rgZhs7Z8lEKVYH6gdWAB8zeI+ViFCtnDrMf+56hFASy9YvCxj5q3j/aylh6ibu/poX1j+eWtMjOc/U/lAybUFn16KKcsQ==";
            var dp = "SZMFswUoUHT4iFA8fS5GyfQ/JI3psOluSIAL4BNOMyK0PP8FDP24Cz5en6LiVTglNpwFOurFOwvHJJyVu/wlAndZOqu2guUzwDLsD8ezoadNOmPhM0/WBt4Nn+iwrFEpREQf4Y4O5cHuM/VQbBKgkQW6kYnLeHef7Vx5Cm3yCpM=";
            var dq = "CCn2W6BrBH6OFEGYpy2ltHTkUR6R6WQ245zEZX8G+3UU9K/FoYwndAEtCVsxtWD/t3kmkLLXJlKU1cqzzl8nBF5rT7boJZfIUSqLWq8iOr/wnpXF7xTWt7OijVaqGn1z1d0T1q49SWho+uYto3miINUy50mCmWf8aqMZM7eWez8=";
            var exponent = "AQAB";
            var inverseQ = "ZIjE/clljkOnzt4QInPRyX8TQcgv3mbwnS3eJIGv9O9URe20QKk91D/WEQMm3LUXyksA43zHx+WNLYX25xWCmonlDZnX1ASmQHJaRK2vCvi+DJgGFoHOZL4pAFsBVaPnepm8gZ+XoHTMJo49Y4XxxQakxwhC43qg6wHmR+x9x4c=";
            var modulus = "xYJVJwa+z5YrzFu3aG0caA2UbZDM4iJzprJLnZPdc/soO85A6aXsfR5q/zQBA5IJY0VgmGsYStvVBu9MLiCowZQwQJUtdsYJLJoFTs7pXqs4qMPg5Zl/8qKpKy/arqC4/RdZlX7nAWo6JHE/cmDeMXf4zEYNzCkm/HZTIHcS+Sr+Zb0wOu1L3jDAeHstrWXRVmQbGQWDQD8g8D3/1xF0qz2pJdM3Kyp0BO/PCZurqqTFoPWmiqV5JNH4Z4BZtPKanDzn+fm62dvRTQpPg23v1xpW2KTogjqpkPEhkI/Yp+Ef9pwRLR8+D6CpKxYdvZ0fPds18uc93kFR+PvBoh5T2Q==";
            var p = "+0gLgB/0wwJEkCVrNrHjX5NCTU/LsAyVSNwGPsWOjeFH3SS6dCFQGUX4vhozhjQJG85DQEN0NfbgllKO/wZFKvMKtos3LE0zExmUADXWGcmG92/AfHVddoJLZxcFXPiXF55mPbAX9TtF/6WNogpH9OCoFiafS3U0q4RVommxiQs=";
            var q = "yTfLZK8X3kMQWVBJPrSB+9I/KJ4vjpkbbBXzs7F79HP1AI0sICLBiBmEboxIEfnAT2pjum5Rj+htaAfbIhP3e0a7j2CNYegdXAb7ZpTukAvgqhAIK2YhXSIz5AEaAnXfxxePI+szeWA3xicj4Lx4xqaIkTmoqzyKgYq4KOW8TSs=";

            return new RSAParameters
            {
                D = Convert.FromBase64String(d),
                DP = Convert.FromBase64String(dp),
                DQ = Convert.FromBase64String(dq),
                Exponent = Convert.FromBase64String(exponent),
                InverseQ = Convert.FromBase64String(inverseQ),
                Modulus = Convert.FromBase64String(modulus),
                P = Convert.FromBase64String(p),
                Q = Convert.FromBase64String(q)
            };
        }
    }
}
