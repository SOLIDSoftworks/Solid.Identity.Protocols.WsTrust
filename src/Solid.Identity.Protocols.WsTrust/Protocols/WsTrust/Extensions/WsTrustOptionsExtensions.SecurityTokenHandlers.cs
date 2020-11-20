using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    public static class WsTrustOptionsExtensions_SecurityTokenHandlers
    {
        public static WsTrustOptions AddSamlSecurityTokenHandler(this WsTrustOptions options)
            => options.AddSecurityTokenHandler(new SamlSecurityTokenHandler(), SamlConstants.Namespace, SamlConstants.OasisWssSamlTokenProfile11);
        public static WsTrustOptions AddSaml2SecurityTokenHandler(this WsTrustOptions options)
            => options.AddSecurityTokenHandler(new Saml2EncryptedSecurityTokenHandler(), Saml2Constants.Saml2TokenProfile11, Saml2Constants.OasisWssSaml2TokenProfile11);
    }
}
