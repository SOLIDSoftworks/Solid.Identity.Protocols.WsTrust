using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public interface IPasswordValidator
    {
        ValueTask<ClaimsPrincipal> ValidatePasswordAsync(string userName, string password);
    }
}
