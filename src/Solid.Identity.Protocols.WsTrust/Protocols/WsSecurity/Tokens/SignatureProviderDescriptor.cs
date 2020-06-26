using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class SignatureProviderDescriptor : CryptoDescriptor<SignatureProvider>
    {
        public SignatureProviderDescriptor(string algorithm, Func<IServiceProvider, object[], SignatureProvider> factory) 
            : base(algorithm, factory)
        {
        }
    }
}
