using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;

namespace Solid.ServiceModel.Security
{
    class WsTrustRequestBodyWriter : BodyWriter
    {
        private WsTrustVersion _version;
        private WsTrustRequest _request;
        private WsTrustSerializer _serializer;

        public WsTrustRequestBodyWriter(WsTrustVersion version, WsTrustSerializer serializer, WsTrustRequest request) 
            : base(true)
        {
            _version = version;
            _request = request;
            _serializer = serializer;
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer) => _serializer.WriteRequest(writer, _version, _request);
    }
}
