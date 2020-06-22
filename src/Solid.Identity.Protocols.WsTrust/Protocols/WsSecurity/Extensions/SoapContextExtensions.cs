using Solid.Identity.Protocols.WsSecurity.Xml;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Extensions.AspNetCore.Soap
{
    internal static class SoapContextExtensions
    {
        private static readonly string WsSecurityTimestampKey = "WS-Security-Timestamp";
        internal static void SetWsSecurityTimestamp(this SoapContext context, Timestamp timestamp)
            => context.HttpContext.Items.Add(WsSecurityTimestampKey, timestamp);

        public static Timestamp GetWsSecurityTimestamp(this SoapContext context)
            => context.HttpContext.Items.TryGetValue(WsSecurityTimestampKey, out var timestamp) ? timestamp as Timestamp : null;
    }
}
