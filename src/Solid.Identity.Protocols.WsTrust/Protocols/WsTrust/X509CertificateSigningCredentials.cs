using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    internal class X509CertificateSigningCredentials : SigningCredentials
    {
        public X509CertificateSigningCredentials(X509Certificate2 certificate) 
            : base(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256)
        {
        }
    }
}
