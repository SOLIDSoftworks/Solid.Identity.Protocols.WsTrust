using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public abstract class PasswordValidator : IPasswordValidator
    {
        public static readonly string AuthenticationType = "Password";
        public static readonly string AuthenticationMethod = "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password";

        public async ValueTask<ClaimsPrincipal> ValidatePasswordAsync(string userName, string password)
        {
            if (!await IsValidAsync(userName, password)) return null;

            var subject = await GetSubjectAsync(userName);
            var claims = await GenerateClaimsAsync(subject, userName);
            var identity = await CreateIdentityAsync(claims);
            return new ClaimsPrincipal(identity);
        }

        protected virtual ValueTask<string> GetSubjectAsync(string userName) => new ValueTask<string>(userName);

        protected virtual ValueTask<ClaimsIdentity> CreateIdentityAsync(IEnumerable<Claim> claims)
        {
            var identity = new ClaimsIdentity(claims, AuthenticationType);
            return new ValueTask<ClaimsIdentity>(identity);
        }

        protected virtual ValueTask<IEnumerable<Claim>> GenerateClaimsAsync(string subject, string userName)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, subject),
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethod),
                AuthenticationInstantClaim.Now
            };

            return new ValueTask<IEnumerable<Claim>>(claims);
        }

        protected abstract ValueTask<bool> IsValidAsync(string userName, string password);
    }
}
