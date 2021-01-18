using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;

namespace Solid.ServiceModel.Security
{
    /// <summary>
    /// A <see cref="ChannelFactory{TChannel}"/> implementation for creating WS-Trust channels.
    /// </summary>
    public class WsTrustChannelFactory : IssuedTokenChannelFactory<IWsTrustChannelContract>
    {
        /// <summary>
        /// Creates a <see cref="WsTrustChannelFactory"/> instance.
        /// </summary>
        /// <param name="binding">The binding to use for the channel.</param>
        /// <param name="remoteAddress">The remote address of the service.</param>
        /// <param name="loggerFactory">An optional <see cref="ILoggerFactory"/> for creating <see cref="ILogger"/>s.</param>
        public WsTrustChannelFactory(Binding binding, EndpointAddress remoteAddress, ILoggerFactory loggerFactory = null) 
            : base(binding, remoteAddress, loggerFactory)
        {
        }

        /// <summary>
        /// The WS-Trust version to use for serialization and deserialization.
        /// </summary>
        public WsTrustVersion TrustVersion { get; set; } = WsTrustVersion.Trust13;

        /// <summary>
        /// Creates a channel.
        /// </summary>
        /// <param name="address">The <see cref="EndpointAddress"/> that provides the location of the service.</param>
        /// <param name="via">The <see cref="Uri"/> that contains the transport address to which the channel sends messages.</param>
        /// <returns>A channel of type <see cref="IWsTrustChannelContract"/>.</returns>
        public override IWsTrustChannelContract CreateChannel(EndpointAddress address, Uri via)
        {
            var channel = base.CreateChannel(address, via);
            var serializer = new WsTrustSerializer();
            serializer.SecurityTokenHandlers.Clear();
            foreach (var handler in GetSupportedSecurityTokenHandlers())
                serializer.SecurityTokenHandlers.Add(handler);
            return new WsTrustChannel(TrustVersion, channel, serializer);
        }
    }
}
