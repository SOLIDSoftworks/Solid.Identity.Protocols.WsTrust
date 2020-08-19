using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsSecurity.Abstractions
{
    public interface IX509Validator
    {
        ValueTask<ClaimsPrincipal> ValidateCertificateAsync(X509Certificate2 certificate);
    }
}
