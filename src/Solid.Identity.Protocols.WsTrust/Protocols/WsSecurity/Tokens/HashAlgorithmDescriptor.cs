using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class HashAlgorithmDescriptor : CryptoDescriptor<HashAlgorithm>
    {
        public HashAlgorithmDescriptor(string algorithm, Func<IServiceProvider, object[], HashAlgorithm> factory) 
            : base(algorithm, factory)
        {
        }
    }
}
