using Solid.Identity.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.Cryptography.X509Certificates
{
    public static class X509Certificate2Extensions
    {
        public static bool HasSubject(this X509Certificate2 certificate, X509Name subject)
        {
            var certificateSubject = X509Name.Parse(certificate.Subject);
            return certificateSubject == subject;
        }

        public static bool HasIssuer(this X509Certificate2 certificate, X509Name issuer)
        {
            var certificateIssuer = X509Name.Parse(certificate.Issuer);
            return certificateIssuer == issuer;
        }
    }
}
