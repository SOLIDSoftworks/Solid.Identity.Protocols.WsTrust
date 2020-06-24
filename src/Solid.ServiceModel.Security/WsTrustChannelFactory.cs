using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading;

namespace Solid.ServiceModel.Security
{
    public class WsTrustChannelFactory : ChannelFactory<IWsTrustChannelContract>
    {
        private WsTrustVersion _trustVersion;
        private Lazy<WsTrustChannelProperties> _lazyProperties;
        private SecurityTokenHandlerCollection _securityTokenHandlers;

        public WsTrustChannelFactory(Binding binding, EndpointAddress remoteAddress)
            : base(binding, remoteAddress)
        {
            _lazyProperties = new Lazy<WsTrustChannelProperties>(InitializeProperties, LazyThreadSafetyMode.ExecutionAndPublication);
            _securityTokenHandlers = new SecurityTokenHandlerCollection();
        }

        public SecurityTokenHandlerCollection SecurityTokenHandlers => _securityTokenHandlers;

        public WsTrustVersion TrustVersion
        {
            get => _trustVersion;
            set
            {
                if (_lazyProperties.IsValueCreated)
                    // TODO: find correct message
                    throw new InvalidOperationException("ID3287");
                _trustVersion = value;
            }
        }

        public override IWsTrustChannelContract CreateChannel(EndpointAddress address, Uri via)
        {
            var inner = base.CreateChannel(address, via);
            var properties = _lazyProperties.Value;
            return new WsTrustChannel(this, inner, properties.TrustVersion);
        }

        //public IWsTrustChannelContract CreateChannelWithIssuedToken(SecurityToken issuedToken)
        //{
        //    TChannel channel = this.CreateChannel();
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.IssuedSecurityToken = issuedToken;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        //public IWsTrustChannelContract CreateChannelWithIssuedToken(SecurityToken issuedToken, EndpointAddress address)
        //{
        //    TChannel channel = this.CreateChannel(address);
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.IssuedSecurityToken = issuedToken;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}


        //public IWsTrustChannelContract CreateChannelWithIssuedToken(SecurityToken issuedToken, EndpointAddress address, Uri via)
        //{
        //    TChannel channel = this.CreateChannel(address, via);
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.IssuedSecurityToken = issuedToken;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        //public IWsTrustChannelContract CreateChannelWithActAsToken(SecurityToken actAsToken)
        //{
        //    TChannel channel = this.CreateChannel();
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.ActAs = actAsToken;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        //public IWsTrustChannelContract CreateChannelWithActAsToken(SecurityToken actAsToken, EndpointAddress address)
        //{
        //    TChannel channel = this.CreateChannel(address);
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.ActAs = actAsToken;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        //public IWsTrustChannelContract CreateChannelWithActAsToken(SecurityToken actAsToken, EndpointAddress address, Uri via)
        //{
        //    TChannel channel = this.CreateChannel(address, via);
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.ActAs = actAsToken;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        //public IWsTrustChannelContract CreateChannelWithOnBehalfOfToken(SecurityToken onBehalfOf)
        //{
        //    TChannel channel = this.CreateChannel();
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.OnBehalfOf = onBehalfOf;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        //public IWsTrustChannelContract CreateChannelWithOnBehalfOfToken(SecurityToken onBehalfOf, EndpointAddress address)
        //{
        //    TChannel channel = this.CreateChannel(address);
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.OnBehalfOf = onBehalfOf;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        //public IWsTrustChannelContract CreateChannelWithOnBehalfOfToken(SecurityToken onBehalfOf, EndpointAddress address, Uri via)
        //{
        //    TChannel channel = this.CreateChannel(address, via);
        //    FederatedClientCredentialsParameters parameters = new FederatedClientCredentialsParameters();
        //    parameters.OnBehalfOf = onBehalfOf;
        //    ((IChannel)channel).GetProperty<ChannelParameterCollection>().Add(parameters);
        //    return channel;
        //}

        private WsTrustChannelProperties InitializeProperties()
            => new WsTrustChannelProperties
            {
                TrustVersion = _trustVersion,
                SecurityTokenHandlers = (_securityTokenHandlers = _securityTokenHandlers.Clone(readOnly: true))
            };

        class WsTrustChannelProperties
        {
            public WsTrustVersion TrustVersion { get; set; }
            public SecurityTokenHandlerCollection SecurityTokenHandlers { get; set; }
        }
    }
}
