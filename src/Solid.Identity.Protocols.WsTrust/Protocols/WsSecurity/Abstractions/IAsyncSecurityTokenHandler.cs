using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public interface IAsyncSecurityTokenHandler
    {
        ValueTask<bool> CanReadTokenAsync(XmlReader reader);
        ValueTask<bool> CanReadTokenAsync(string tokenString);
        ValueTask<bool> CanWriteSecurityTokenAsync(SecurityToken securityToken);
        ValueTask<SecurityKeyIdentifierClause> CreateSecurityTokenReferenceAsync(SecurityToken token, bool attached);
        ValueTask<SecurityToken> CreateTokenAsync(SecurityTokenDescriptor tokenDescriptor);
        ValueTask<SecurityToken> ReadTokenAsync(string securityToken);
        ValueTask<SecurityToken> ReadTokenAsync(XmlReader securityToken);
        ValueTask<SecurityToken> ReadTokenAsync(XmlReader securityToken, TokenValidationParameters validationParameters);
        ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(string securityToken, TokenValidationParameters validationParameters);
        ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(XmlReader securityToken, TokenValidationParameters validationParameters);
    }

    public class SecurityTokenValidationResult
    {
        public ClaimsPrincipal User { get; set; }
        public SecurityToken Token { get; set; }
        public bool Success { get; set; }
        public Exception Error { get; set; }
    }
}
