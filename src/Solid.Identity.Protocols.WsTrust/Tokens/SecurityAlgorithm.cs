using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Tokens
{
    public abstract class SecurityAlgorithm
    {
        public abstract string Algorithm { get; }
        public abstract string Digest { get; }

        public static class Asymmetric
        {
            public static readonly SecurityAlgorithm RsaSha256 = new RsaSha256();
            public static readonly SecurityAlgorithm RsaSha384 = new RsaSha384();
            public static readonly SecurityAlgorithm RsaSha512 = new RsaSha512();
        }
    }

    internal class RsaSha256 : SecurityAlgorithm
    {
        public override string Algorithm => SecurityAlgorithms.RsaSha256Signature;
        public override string Digest => SecurityAlgorithms.Sha256Digest;
    }

    internal class RsaSha384 : SecurityAlgorithm
    {
        public override string Algorithm => SecurityAlgorithms.RsaSha384Signature;
        public override string Digest => SecurityAlgorithms.Sha384Digest;
    }

    internal class RsaSha512 : SecurityAlgorithm
    {
        public override string Algorithm => SecurityAlgorithms.RsaSha512Signature;
        public override string Digest => SecurityAlgorithms.Sha512Digest;
    }
}
