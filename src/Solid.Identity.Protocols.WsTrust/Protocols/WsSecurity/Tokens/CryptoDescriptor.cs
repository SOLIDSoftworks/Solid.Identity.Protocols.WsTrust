using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    class CryptoDescriptor<T>
    {
        protected CryptoDescriptor(string algorithm, Func<IServiceProvider, object[], T> factory)
        {
            SupportedAlgorithm = algorithm;
            Factory = factory;
        }

        public string SupportedAlgorithm { get; }
        public Func<IServiceProvider, object[], T> Factory { get; }
    }
}
