using Microsoft.AspNetCore.Authentication;
using Solid.Identity.Protocols.WsSecurity.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Tests.Host
{
    class TestX509Validator : X509Validator
    {
        private ISystemClock _clock;

        public TestX509Validator(ISystemClock clock) => _clock = clock;

        protected override ValueTask<bool> IsValidAsync(X509Certificate2 certificate)
        {
            var now = _clock.UtcNow;
            return new ValueTask<bool>(certificate.NotBefore <= now && now <= certificate.NotAfter && certificate.Subject == "CN=test.valid");
        }
    }
}
