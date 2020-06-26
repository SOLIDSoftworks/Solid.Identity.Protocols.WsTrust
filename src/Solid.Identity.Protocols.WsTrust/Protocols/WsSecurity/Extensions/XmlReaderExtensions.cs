using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Text;

namespace System.Xml
{
    internal static class XmlReaderExtensions
    {
        public static bool IsWsSecurity(this XmlReader reader) => reader.IsStartElement("Security", WsSecurityConstants.WsSecurity10.Namespace);
        public static bool IsWsSecurityEndElement(this XmlReader reader) => reader.IsEndElement("Security", WsSecurityConstants.WsSecurity10.Namespace);
        public static bool IsWsSecurityTimestamp(this XmlReader reader) => reader.IsStartElement("Timestamp", WsUtilityConstants.WsUtility10.Namespace);
        public static bool IsXmlSignature(this XmlReader reader) => reader.IsStartElement("Signature", XmlSignatureConstants.Namespace);
        public static bool IsEndElement(this XmlReader reader, string localName, string ns)
        {
            if (reader.NodeType != XmlNodeType.EndElement) return false;
            return reader.LocalName == localName && reader.NamespaceURI == ns;
        }
    }
}
