using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.ServiceModel.Security
{
    public static class WsTrustRequestTypes
    {
        public const string Cancel = "http://schemas.microsoft.com/idfx/requesttype/cancel";
        public const string Issue = "http://schemas.microsoft.com/idfx/requesttype/issue";
        public const string Renew = "http://schemas.microsoft.com/idfx/requesttype/renew";
        public const string Validate = "http://schemas.microsoft.com/idfx/requesttype/validate";

    }
}
