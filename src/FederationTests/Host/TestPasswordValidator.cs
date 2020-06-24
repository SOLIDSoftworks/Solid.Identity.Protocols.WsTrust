using Solid.Identity.Protocols.WsSecurity.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Tests.Host
{
    class TestPasswordValidator : PasswordValidator
    {
        protected override ValueTask<bool> IsValidAsync(string userName, string password)
            => new ValueTask<bool>(userName == "userName" && password == "password");
    }
}
