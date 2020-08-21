using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public abstract class X509Validator : IX509Validator
    {
        public static readonly string AuthenticationType = "X509";
        public static readonly string AuthenticationMethod = "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/x509";
        public static readonly Regex CommonNameRegex = new Regex("CN=([^ ])*?");

        public async ValueTask<ClaimsPrincipal> ValidateCertificateAsync(X509Certificate2 certificate)
        {
            if (!await IsValidAsync(certificate)) return null;

            var name = await GetCommonNameAsync(certificate);
            var claims = await GenerateClaimsAsync(name, certificate);
            var identity = await CreateIdentityAsync(claims);
            return new ClaimsPrincipal(identity);
        }

        protected virtual ValueTask<ClaimsIdentity> CreateIdentityAsync(IEnumerable<Claim> claims)
        {
            var identity = new ClaimsIdentity(claims, AuthenticationType);
            return new ValueTask<ClaimsIdentity>(identity);
        }

        protected virtual ValueTask<string> GetCommonNameAsync(X509Certificate2 certificate)
        {
            var match = CommonNameRegex.Match(certificate.Subject);
            if (!match.Success) return new ValueTask<string>(certificate.Subject);
            return new ValueTask<string>(match.Groups[1].Value);
        }

        protected virtual ValueTask<IEnumerable<Claim>> GenerateClaimsAsync(string name, X509Certificate2 certificate)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, certificate.Thumbprint),
                new Claim(ClaimTypes.Name, name),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethod),
                new Claim(ClaimTypes.X500DistinguishedName, certificate.Subject),
                AuthenticationInstantClaim.Now
            };

            return new ValueTask<IEnumerable<Claim>>(claims);
        }

        protected abstract ValueTask<bool> IsValidAsync(X509Certificate2 certificate);
    }
}
