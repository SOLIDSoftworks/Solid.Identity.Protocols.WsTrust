using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    internal static class MicrosoftKeyTypes
    {
        public const string Symmetric = "http://schemas.microsoft.com/idfx/keytype/symmetric";
        public const string Asymmetric = "http://schemas.microsoft.com/idfx/keytype/asymmetric";
        public const string Bearer = "http://schemas.microsoft.com/idfx/keytype/bearer";
    }
}
