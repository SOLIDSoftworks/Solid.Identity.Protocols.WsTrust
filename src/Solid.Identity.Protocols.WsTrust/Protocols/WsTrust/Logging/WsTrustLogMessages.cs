using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;

namespace Solid.Identity.Protocols.WsTrust.Logging
{
    internal static class WsTrustLogMessages
    {
        public static readonly Action<ILogger, WsTrustMessageInformation, Exception> WsTrustMessage 
            = LoggerMessage.Define<WsTrustMessageInformation>(LogLevel.Information, 0, "Incoming WS-Trust request" + Environment.NewLine + "{message}");

        public static readonly Action<ILogger, string, UnableToGetAllClaims, Exception> UnableToGetAllClaims
            = LoggerMessage.Define<string, UnableToGetAllClaims>(LogLevel.Debug, 0, "Unable to get all {requirement} claim values" + Environment.NewLine + "{model}");
    }
}
