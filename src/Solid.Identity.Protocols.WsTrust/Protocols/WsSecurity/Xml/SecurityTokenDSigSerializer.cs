using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Xml
{
    class SecurityTokenDSigSerializer : DSigSerializer
    {
        private List<Reference> _references = new List<Reference>();        

        public override Reference ReadReference(XmlReader reader)
        {
            var reference = base.ReadReference(reader);
            while (reader.IsStartElement(XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace))
                _references.Add(base.ReadReference(reader));
            return reference;
        }

        public override SignedInfo ReadSignedInfo(XmlReader reader)
        {
            var info = base.ReadSignedInfo(reader);
            foreach (var reference in _references)
                info.References.Add(reference);
            return info;
        }

        //public override KeyInfo ReadKeyInfo(XmlReader reader)
        //{
        //    XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

        //    var keyInfo = new KeyInfo
        //    {
        //        Prefix = reader.Prefix
        //    };

        //    try
        //    {
        //        bool isEmptyElement = reader.IsEmptyElement;

        //        // <KeyInfo>
        //        reader.ReadStartElement();
        //        while (reader.IsStartElement())
        //        {
        //            // <SignatureReference>
        //            if (reader.IsStartElement("SecurityTokenReference", WsSecurityConstants.WsSecurity10.Namespace))
        //            {
        //                reader.ReadStartElement(); 
        //                if (reader.IsStartElement(XmlSignatureConstants.Elements.RetrievalMethod, XmlSignatureConstants.Namespace))
        //                {
        //                    keyInfo.RetrievalMethodUri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI);
        //                    reader.ReadOuterXml();
        //                }
        //                return ReadSecurityTokenReference(reader));
        //            }
        //            // <RetrievalMethod>
        //            else if (reader.IsStartElement(XmlSignatureConstants.Elements.RetrievalMethod, XmlSignatureConstants.Namespace))
        //            {
        //                keyInfo.RetrievalMethodUri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI);
        //                reader.ReadOuterXml();
        //            }
        //            // <KeyName>
        //            else if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyName, XmlSignatureConstants.Namespace))
        //            {
        //                keyInfo.KeyName = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.KeyName, XmlSignatureConstants.Namespace);
        //            }
        //            // <KeyValue>
        //            else if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyValue, XmlSignatureConstants.Namespace))
        //            {
        //                reader.ReadStartElement(XmlSignatureConstants.Elements.KeyValue, XmlSignatureConstants.Namespace);
        //                if (reader.IsStartElement(XmlSignatureConstants.Elements.RSAKeyValue, XmlSignatureConstants.Namespace))
        //                {
        //                    // Multiple RSAKeyValues were found
        //                    if (keyInfo.RSAKeyValue != null)
        //                        throw XmlUtil.LogReadException(LogMessages.IDX30015, XmlSignatureConstants.Elements.RSAKeyValue);

        //                    keyInfo.RSAKeyValue = ReadRSAKeyValue(reader);
        //                }
        //                else
        //                {
        //                    // Skip the element since it is not an <RSAKeyValue>
        //                    LogHelper.LogWarning(LogMessages.IDX30300, reader.ReadOuterXml());
        //                }

        //                // </KeyValue>
        //                reader.ReadEndElement();
        //            }
        //            else
        //            {
        //                // Skip the element since it is not one of  <RetrievalMethod>, <X509Data>, <KeyValue>
        //                LogHelper.LogWarning(LogMessages.IDX30300, reader.ReadOuterXml());
        //            }
        //        }

        //        // </KeyInfo>
        //        if (!isEmptyElement)
        //            reader.ReadEndElement();

        //    }
        //    catch (Exception ex)
        //    {
        //        if (ex is XmlReadException)
        //            throw;

        //        throw XmlUtil.LogReadException(LogMessages.IDX30017, ex, XmlSignatureConstants.Elements.KeyInfo, ex);
        //    }

        //    return keyInfo;
        //}

        private KeyInfo ReadSecurityTokenReference(XmlReader reader)
        {
            throw new NotImplementedException();
        }
    }
}
