using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;

namespace Solid.Identity.Protocols.WsTrust
{
    internal class WsTrustResponseObjectSerializer : XmlObjectSerializer
    {
        private WsTrustVersion _version;
        private WsTrustSerializer _inner;

        public WsTrustResponseObjectSerializer(WsTrustVersion version, WsTrustSerializer inner)
        {
            _version = version;
            _inner = inner;
        }
        public override bool IsStartObject(XmlDictionaryReader reader) => throw new NotSupportedException();

        public override object ReadObject(XmlDictionaryReader reader, bool verifyObjectName) => throw new NotSupportedException();

        public override void WriteEndObject(XmlDictionaryWriter writer)
        {
        }

        public override void WriteObjectContent(XmlDictionaryWriter writer, object graph)
        {
            var response = graph as WsTrustResponse;
            if (graph == null)
                throw new ArgumentException($"Cannot serialize {graph.GetType().Name} using WsTrustResponseSerializer.");

            _inner.WriteResponse(writer, _version, response);
        }

        public override void WriteStartObject(XmlDictionaryWriter writer, object graph)
        {
        }
    }
}
