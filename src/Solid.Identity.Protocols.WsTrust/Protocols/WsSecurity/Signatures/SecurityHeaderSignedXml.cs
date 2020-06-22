using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Signatures
{
    internal class SecurityHeaderSignedXml : SignedXml
    {
        public SecurityHeaderSignedXml()
        {
        }

        public SecurityHeaderSignedXml(XmlDocument document) : base(document)
        {
        }

        public SecurityHeaderSignedXml(XmlElement elem) : base(elem)
        {
        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            var element = base.GetIdElement(document, idValue);
            if (element != null) return element;

            var elements = Flatten(document.DocumentElement);
            return elements
                .Where(e => e.HasAttribute("Id", WsUtilityConstants.WsUtility10.Namespace))
                .FirstOrDefault(e => e.GetAttribute("Id", WsUtilityConstants.WsUtility10.Namespace) == idValue);
        }

        private IEnumerable<XmlElement> Flatten(XmlElement element)
        {
            yield return element;
            foreach (var child in element.ChildNodes.OfType<XmlElement>())
                foreach (var descendant in Flatten(child))
                    yield return descendant;
        }
    }
}
