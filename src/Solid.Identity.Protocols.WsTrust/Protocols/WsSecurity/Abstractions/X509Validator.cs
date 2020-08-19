using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public abstract class X509Validator : IX509Validator
    {
        public static readonly string AuthenticationType = "X509";
        public static readonly string AuthenticationMethod = "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/x509";

        public async ValueTask<ClaimsPrincipal> ValidateCertificateAsync(X509Certificate2 certificate)
        {
            if (!await IsValidAsync(certificate)) return null;

            var subject = await GetSubjectAsync(certificate);
            var claims = await GenerateClaimsAsync(subject, certificate);
            var identity = await CreateIdentityAsync(claims);
            return new ClaimsPrincipal(identity);
        }

        protected virtual ValueTask<ClaimsIdentity> CreateIdentityAsync(IEnumerable<Claim> claims)
        {
            var identity = new ClaimsIdentity(claims, AuthenticationType);
            return new ValueTask<ClaimsIdentity>(identity);
        }
        
        protected virtual ValueTask<string> GetSubjectAsync(X509Certificate2 certificate)
            => new ValueTask<string>(certificate.Subject);

        protected virtual ValueTask<IEnumerable<Claim>> GenerateClaimsAsync(string subject, X509Certificate2 certificate)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, subject),
                new Claim(ClaimTypes.Name, certificate.Subject),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethod),
                AuthenticationInstantClaim.Now
            };

            return new ValueTask<IEnumerable<Claim>>(claims);
        }

        protected abstract ValueTask<bool> IsValidAsync(X509Certificate2 certificate);
    }
}
