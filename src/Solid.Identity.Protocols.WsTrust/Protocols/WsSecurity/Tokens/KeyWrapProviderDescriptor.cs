using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class KeyWrapProviderDescriptor : CryptoDescriptor<KeyWrapProvider>
    {
        public KeyWrapProviderDescriptor(string algorithm, Func<IServiceProvider, object[], KeyWrapProvider> factory) 
            : base(algorithm, factory)
        {
        }
    }
}
