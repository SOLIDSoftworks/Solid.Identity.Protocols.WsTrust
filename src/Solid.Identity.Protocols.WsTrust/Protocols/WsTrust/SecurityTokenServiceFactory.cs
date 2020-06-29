using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.Abstractions;

namespace Solid.Identity.Protocols.WsTrust
{
    public sealed class SecurityTokenServiceFactory
    {
        private IServiceProvider _services;

        public SecurityTokenServiceFactory(IServiceProvider services)
        {
            _services = services;
        }
        public ISecurityTokenService Create(WsTrustConstants constants)
        {
            var sts = _services.GetService<SecurityTokenService>();
            sts.Initialize(constants);
            return sts;
        }
    }
}
