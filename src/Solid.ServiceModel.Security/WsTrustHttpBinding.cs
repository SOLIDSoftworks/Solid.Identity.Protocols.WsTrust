using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;

namespace Solid.ServiceModel.Security
{
    public class WsTrustHttpBinding : WSHttpBinding
    {
        public WsTrustHttpBinding()
            : base(SecurityMode.TransportWithMessageCredential, false)
        {
        }

        protected override SecurityBindingElement CreateMessageSecurity()
        {
            return base.CreateMessageSecurity();
        }
    }
}
