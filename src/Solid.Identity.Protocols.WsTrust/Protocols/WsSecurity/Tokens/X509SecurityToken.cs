using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class X509SecurityToken : SecurityToken
    {
        public X509SecurityToken(string id, X509Certificate2 certificate)
        {
            Id = id;
            Certificate = certificate;
            SecurityKey = new X509SecurityKey(certificate);
        }

        public override string Id { get; }
        public X509Certificate2 Certificate { get; }

        public override string Issuer => Certificate.Issuer;

        public override SecurityKey SecurityKey { get; }

        public override SecurityKey SigningKey { get; set; }

        public override DateTime ValidFrom => Certificate.NotBefore;

        public override DateTime ValidTo => Certificate.NotAfter;
    }
}
