using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;

namespace Solid.Identity.Protocols.WsSecurity.Xml
{
    class WsUtilityDSigSerializer : DSigSerializer
    {
        private readonly List<Reference> _references = new List<Reference>();
        private readonly XmlReader _document;

        public WsUtilityDSigSerializer(XmlReader document)
        {
            _document = document;
        }

        public override Signature ReadSignature(XmlReader reader)
        {
            using var activity = Tracing.WsSecurity.Xml.StartActivity($"{nameof(WsUtilityDSigSerializer)}.{nameof(ReadSignature)}");
            return base.ReadSignature(reader);
        }

        public override Reference ReadReference(XmlReader reader)
        {
            var reference = ReadSingleReference(reader);
            while (reader.IsStartElement(XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace))
                _references.Add(ReadSingleReference(reader));
            return reference;
        }

        private Reference ReadSingleReference(XmlReader reader)
        {
            var reference = base.ReadReference(reader);
            if(reference.CanonicalizingTransfrom != null && !reference.Transforms.Any())
                reference.Transforms.Add(new NullTransform());
            return reference;
        }

        public override SignedInfo ReadSignedInfo(XmlReader reader)
        {
            var info = base.ReadSignedInfo(reader);
            foreach (var reference in _references)
                info.References.Add(reference);

            while(_document.Read())
            {
                if (!_document.IsStartElement()) continue;
                if (!_document.HasAttributes) continue;
                var id = _document.GetAttribute("Id", WsUtilityConstants.WsUtility10.Namespace);
                if (id == null) continue;

                var reference = info
                    .References
                    .FirstOrDefault(r => r.Uri == $"#{id}")
                ;
                if (reference != null)
                    reference.TokenStream = GetXmlTokenStream(_document);

                if (info.References.All(r => r.TokenStream != null)) break;
            }

            return info;
        }

        private XmlTokenStream GetXmlTokenStream(XmlReader reader)
        {
            using (var dictionaryReader = XmlDictionaryReader.CreateDictionaryReader(reader.ReadSubtree()))
            using (var xmlTokenStreamReader = new XmlTokenStreamReader(dictionaryReader))
            {
                _ = xmlTokenStreamReader.ReadOuterXml();
                return xmlTokenStreamReader.TokenStream;
            }

        }

        public override KeyInfo ReadKeyInfo(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

            var keyInfo = new WsSecurityKeyInfo
            {
                Prefix = reader.Prefix
            };

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;

                // <KeyInfo>
                reader.ReadStartElement();
                while (reader.IsStartElement())
                {
                    // <SecurityTokenReference>
                    if (reader.IsStartElement("SecurityTokenReference", WsSecurityConstants.WsSecurity10.Namespace))
                    {
                        //<o:SecurityTokenReference>
                        //  <o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#uuid-2a7d35cf-97d9-4177-8b84-8a74f5dcd8a2-29"></o:Reference>
                        //</o:SecurityTokenReference>
                        reader.ReadStartElement();
                        if (reader.IsStartElement("Reference", WsSecurityConstants.WsSecurity10.Namespace))
                        {
                            var uri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI);
                            keyInfo.SecurityTokenReference = new WsSecurityTokenReference(new KeyIdentifier(uri))
                            {
                                Reference = new WsSecurityReference
                                {
                                    ValueType = reader.GetAttribute("ValueType"),
                                    Uri = uri
                                }
                                //Reference = new WsSecurityReference()
                                //{
                                //    ValueType = reader.GetAttribute("ValueType"),
                                //    Uri = uri
                                //}
                            };
                            _ = reader.ReadOuterXml();
                        }
                        reader.ReadEndElement();
                    }
                    else
                    {
                        //LogHelper.LogWarning(LogMessages.IDX30300, reader.ReadOuterXml());
                        _ = reader.ReadOuterXml(); // TODO: log this somehow
                    }
                }

                // </KeyInfo>
                if (!isEmptyElement)
                    reader.ReadEndElement();

            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw new XmlReadException($"{ "IDX30017" }: Could not read {XmlSignatureConstants.Elements.KeyInfo} element.", ex);// XmlUtil.LogReadException(LogMessages.IDX30017, ex, XmlSignatureConstants.Elements.KeyInfo, ex);
            }

            return keyInfo;
        }
    }

    static class KeyInfoExtensions
    {
        public static WsSecurityTokenReference GetSecurityTokenReference(this KeyInfo keyInfo)
            => (keyInfo as WsSecurityKeyInfo)?.SecurityTokenReference;
    }
}
