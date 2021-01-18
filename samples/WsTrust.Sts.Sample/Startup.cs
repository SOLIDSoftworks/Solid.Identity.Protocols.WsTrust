using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace WsTrust.Sts.Sample
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            var parameters = CreateRsaParameters();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameters);

            services.AddLogging(logging => logging.ClearProviders());
            services.AddWsTrust(builder =>
            {
                builder.Configure(wstrust =>
                {
                    wstrust.Issuer = "urn:sample:issuer";

                    wstrust.AddSaml2SecurityTokenHandler();

                    wstrust.AddIdentityProvider("urn:sample.identityprovider", idp =>
                    {
                        idp.SecurityKeys.Add(new RsaSecurityKey(rsa));
                        idp.RestrictRelyingParties = false;
                        idp.Name = "Sample IDP";
                    });

                    wstrust.AddRelyingParty("urn:sample:relyingparty", party =>
                    {
                        party.Name = "Sample RP";
                        party.SigningKey = new RsaSecurityKey(rsa);
                    });
                });

                
                builder.AddWsTrust13AsyncContract();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapWsTrust13AsyncService();
            });
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
