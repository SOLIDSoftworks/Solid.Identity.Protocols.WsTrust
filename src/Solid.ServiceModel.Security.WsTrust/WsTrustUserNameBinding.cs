using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;

namespace Solid.ServiceModel.Security
{
    /// <summary>
    /// A <see cref="Binding"/> that is used when performing a WS-Trust request.
    /// </summary>
    public class WsTrustUserNameBinding : WSHttpBinding
    {
        /// <summary>
        /// Creates a <see cref="WsTrustUserNameBinding"/> instance.
        /// </summary>
        public WsTrustUserNameBinding()
            : base(SecurityMode.TransportWithMessageCredential, false)
        {
            AllowCookies = false;
            Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            Security.Message.NegotiateServiceCredential = false;
            Security.Message.EstablishSecurityContext = false;
        }

        /// <summary>
        /// Returns a value that indicates whether the current binding can build a channel factory stack on the client that satisfies the collection of binding parameters specified.
        /// </summary>
        /// <typeparam name="TChannel">The type of channel for which the factory is being tested.</typeparam>
        /// <param name="parameters">The <see cref="BindingParameterCollection"/> that specifies requirements for the channel factory that is built.</param>
        /// <returns><code>true</code> if the specified channel factory stack can be build on the client; otherwise, <code>false</code>.</returns>
        public override bool CanBuildChannelFactory<TChannel>(BindingParameterCollection parameters)
        {
            var type = typeof(TChannel);
            return base.CanBuildChannelFactory<TChannel>() && type == typeof(IWsTrustChannelContract);
        }

        /// <summary>
        /// Returns the security binding element from the current binding.
        /// </summary>
        /// <returns>A <see cref="SecurityBindingElement"/> from the current binding.</returns>
        protected override SecurityBindingElement CreateMessageSecurity()
        {
            var element = SecurityBindingElement.CreateUserNameOverTransportBindingElement();
            element.IncludeTimestamp = true;
            return element;
        }
    }
}
