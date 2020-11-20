//using Microsoft.IdentityModel.Tokens;
//using System;
//using System.Collections.Generic;
//using System.Security.Cryptography.Xml;
//using System.Text;

//namespace Solid.Identity.Tokens
//{
//    public abstract class EncryptionAlgorithm
//    {
//        public abstract string KeyWrapAlgorithm { get; }
//        public abstract string DataEncryptionAlgorithm { get; }

//        public static EncryptionAlgorithm Aes128 => new Aes128();

//        public static EncryptionAlgorithm Aes192 => new Aes192();

//        public static EncryptionAlgorithm Aes256 => new Aes256();
//    }

//    internal class Aes128 : EncryptionAlgorithm
//    {
//        public override string KeyWrapAlgorithm => EncryptedXml.XmlEncAES128KeyWrapUrl;

//        public override string DataEncryptionAlgorithm => EncryptedXml.XmlEncAES128Url;
//    }

//    internal class Aes192 : EncryptionAlgorithm
//    {
//        public override string KeyWrapAlgorithm => EncryptedXml.XmlEncAES192KeyWrapUrl;

//        public override string DataEncryptionAlgorithm => EncryptedXml.XmlEncAES192Url;
//    }

//    internal class Aes256 : EncryptionAlgorithm
//    {
//        public override string KeyWrapAlgorithm => EncryptedXml.XmlEncAES256KeyWrapUrl;

//        public override string DataEncryptionAlgorithm => EncryptedXml.XmlEncAES256Url;
//    }
//}
