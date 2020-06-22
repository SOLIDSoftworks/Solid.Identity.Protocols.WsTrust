using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    public class WsTrustSerializerFactory
    {
        public WsTrustSerializerFactory(SecurityTokenHandlerProvider provider)
        {
            SecurityTokenHandlerProvider = provider;
        }

        protected SecurityTokenHandlerProvider SecurityTokenHandlerProvider { get; }

        public WsTrustSerializer Create()
        {
            var serializer = new WsTrustSerializer();
            serializer.SecurityTokenHandlers.Clear();
            var handlers = SecurityTokenHandlerProvider.GetAllSecurityTokenHandlers();
            foreach (var handler in handlers)
                serializer.SecurityTokenHandlers.Add(handler);
            return serializer;
        }
    }
}
