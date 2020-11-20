//using Microsoft.IdentityModel.Tokens;
//using System;
//using System.Collections.Generic;
//using System.Text;

//namespace Solid.Identity.Tokens
//{
//    public abstract class SigningAlgorithm
//    {
//        public abstract string Algorithm { get; }
//        public abstract string Digest { get; }

//        public static readonly SigningAlgorithm RsaSha256 = new RsaSha256();
//        public static readonly SigningAlgorithm RsaSha384 = new RsaSha384();
//        public static readonly SigningAlgorithm RsaSha512 = new RsaSha512();
//    }

//    internal class RsaSha256 : SigningAlgorithm
//    {
//        public override string Algorithm => SecurityAlgorithms.RsaSha256Signature;
//        public override string Digest => SecurityAlgorithms.Sha256Digest;
//    }

//    internal class RsaSha384 : SigningAlgorithm
//    {
//        public override string Algorithm => SecurityAlgorithms.RsaSha384Signature;
//        public override string Digest => SecurityAlgorithms.Sha384Digest;
//    }

//    internal class RsaSha512 : SigningAlgorithm
//    {
//        public override string Algorithm => SecurityAlgorithms.RsaSha512Signature;
//        public override string Digest => SecurityAlgorithms.Sha512Digest;
//    }
//}
