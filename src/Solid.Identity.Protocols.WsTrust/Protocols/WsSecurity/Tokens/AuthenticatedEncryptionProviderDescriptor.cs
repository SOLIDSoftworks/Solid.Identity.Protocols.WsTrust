using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class AuthenticatedEncryptionProviderDescriptor : CryptoDescriptor<AuthenticatedEncryptionProvider>
    {
        public AuthenticatedEncryptionProviderDescriptor(string algorithm, Func<IServiceProvider, object[], AuthenticatedEncryptionProvider> factory)
            : base(algorithm, factory)
        {
        }
    }
}
