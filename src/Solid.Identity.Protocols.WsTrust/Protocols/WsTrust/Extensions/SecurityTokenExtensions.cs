using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace Microsoft.IdentityModel.Tokens
{
    internal static class SecurityTokenExtensions
    {
        public static XmlElement ConvertToXmlElement(this SecurityToken token, SecurityTokenHandler handler)
        {
            using(var stream = new MemoryStream())
            {
                using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { Encoding = new UTF8Encoding(false), Indent = false, OmitXmlDeclaration = true, CloseOutput = false }))
                    handler.WriteToken(writer, token);
                stream.Position = 0;
                var document = new XmlDocument();
                document.Load(stream);
                return document.DocumentElement;
            }
        }
    }
}
