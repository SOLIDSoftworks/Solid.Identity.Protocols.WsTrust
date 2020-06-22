using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    internal class SecurityTokenHandlerDescriptor
    {
        public SecurityTokenHandlerDescriptor(IEnumerable<string> tokenTypes, Func<IServiceProvider, SecurityTokenHandler> factory)
        {
            TokenTypeIdentifiers = tokenTypes;
            Factory = factory;
        }

        public IEnumerable<string> TokenTypeIdentifiers { get; }
        public Func<IServiceProvider, SecurityTokenHandler> Factory { get; }
    }
}
