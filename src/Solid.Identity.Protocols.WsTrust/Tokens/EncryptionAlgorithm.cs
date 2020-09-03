using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Text;

namespace Solid.Identity.Tokens
{
    public abstract class EncryptionAlgorithm
    {
        public abstract string KeyWrapAlgorithm { get; }
        public abstract string DataEncryptionAlgorithm { get; }

        public static EncryptionAlgorithm Aes128 => new Aes128();
    }

    internal class Aes128 : EncryptionAlgorithm
    {
        public override string KeyWrapAlgorithm => EncryptedXml.XmlEncAES128KeyWrapUrl;

        public override string DataEncryptionAlgorithm => EncryptedXml.XmlEncAES128Url;
    }
}
