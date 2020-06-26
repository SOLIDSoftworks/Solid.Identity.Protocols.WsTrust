using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Xml
{
    class NullTransform : Transform
    {
        public override string Algorithm => "null";

        public override XmlTokenStream Process(XmlTokenStream tokenStream) => tokenStream;
    }
}
