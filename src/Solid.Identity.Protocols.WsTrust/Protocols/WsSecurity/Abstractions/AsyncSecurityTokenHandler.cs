using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public abstract class AsyncSecurityTokenHandler : SecurityTokenHandler, IAsyncSecurityTokenHandler
    {
        // TODO: Remove override if/when our PR for CanWriteSecurityToken default implementation gets accepted and released.
        // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/1438
        public override bool CanWriteSecurityToken(SecurityToken securityToken) 
            => CanWriteToken && securityToken != null && TokenType.IsAssignableFrom(securityToken.GetType());

        public virtual ValueTask<bool> CanReadTokenAsync(XmlReader reader) => new ValueTask<bool>(CanReadToken(reader));

        public virtual ValueTask<bool> CanReadTokenAsync(string tokenString) => new ValueTask<bool>(CanReadToken(tokenString));

        public virtual ValueTask<bool> CanWriteSecurityTokenAsync(SecurityToken securityToken) => new ValueTask<bool>(CanWriteSecurityToken(securityToken));

        public virtual ValueTask<SecurityKeyIdentifierClause> CreateSecurityTokenReferenceAsync(SecurityToken token, bool attached)
            => new ValueTask<SecurityKeyIdentifierClause>(CreateSecurityTokenReference(token, attached));

        public virtual ValueTask<SecurityToken> CreateTokenAsync(SecurityTokenDescriptor tokenDescriptor) => new ValueTask<SecurityToken>(CreateToken(tokenDescriptor));

        public virtual ValueTask<SecurityToken> ReadTokenAsync(string securityToken) => new ValueTask<SecurityToken>(ReadToken(securityToken));

        public virtual ValueTask<SecurityToken> ReadTokenAsync(XmlReader securityToken) => new ValueTask<SecurityToken>(ReadToken(securityToken));

        public virtual ValueTask<SecurityToken> ReadTokenAsync(XmlReader securityToken, TokenValidationParameters validationParameters) => new ValueTask<SecurityToken>(ReadToken(securityToken, validationParameters));

        public virtual ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(string securityToken, TokenValidationParameters validationParameters)
        {
            try
            {
                var user = ValidateToken(securityToken, validationParameters, out var token);
                return new ValueTask<SecurityTokenValidationResult>(new SecurityTokenValidationResult { User = user, Token = token, Success = true });
            }
            catch(Exception ex)
            {
                return new ValueTask<SecurityTokenValidationResult>(new SecurityTokenValidationResult { Error = ex });
            }
        }

        public virtual ValueTask<SecurityTokenValidationResult> ValidateTokenAsync(XmlReader securityToken, TokenValidationParameters validationParameters)
        {
            try
            { 
                var user = ValidateToken(securityToken, validationParameters, out var token);
                return new ValueTask<SecurityTokenValidationResult>(new SecurityTokenValidationResult { User = user, Token = token, Success = true });
            }
            catch (Exception ex)
            {
                return new ValueTask<SecurityTokenValidationResult>(new SecurityTokenValidationResult { Error = ex });
            }
        }
    }
}
