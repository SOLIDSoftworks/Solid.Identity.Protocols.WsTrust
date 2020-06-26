using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public interface ITokenValidationParametersFactory
    {
        ValueTask<TokenValidationParameters> CreateAsync();
    }
}
