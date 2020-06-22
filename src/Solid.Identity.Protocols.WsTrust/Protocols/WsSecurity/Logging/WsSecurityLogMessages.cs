using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Solid.Identity.Protocols.WsSecurity.Logging
{
    internal static class WsSecurityLogMessages
    {
        public static void LogTimestampElement(ILogger logger, ref XmlReader reader)
        {
            if (!logger.IsEnabled(LogLevel.Debug)) return;

            var element = XNode.ReadFrom(reader);
            reader = CreateBufferedReader(element);
            var xml = element.ToString();
            LogTimestampElementValue(logger, element.ToString(), null);
        }
        public static void LogSignatureElement(ILogger logger, ref XmlReader reader)
        {
            if (!logger.IsEnabled(LogLevel.Trace)) return;

            var element = XNode.ReadFrom(reader);
            reader = CreateBufferedReader(element);
            var xml = element.ToString();
            LogSignatureElementValue(logger, element.ToString(), null);
        }

        public static void LogSecurityTokenElement(ILogger logger, ref XmlReader reader) 
        {
            if (!logger.IsEnabled(LogLevel.Debug)) return;

            var node = XNode.ReadFrom(reader);
            reader = CreateBufferedReader(node);
            if (node is XElement element)
            {
                LogSecurityTokenElementMetadata(logger, new SecurityTokenElementLogMessageState { Name = element.Name.LocalName, Namespace = element.Name.NamespaceName }, null);

                if (!logger.IsEnabled(LogLevel.Trace)) return;
                LogSecurityTokenValue(logger, element.ToString(), null);
            }
        }


        //public static void LogTimestampElement(ILogger logger, XElement element)
        //{
        //    if (!logger.IsEnabled(LogLevel.Debug)) return;
        //    LogTimestampElementValue(logger, element.ToString(), null);
        //}

        //public static readonly Action<ILogger, XElement> LogSecurityTokenElement = (logger, element) =>
        //{
        //    if (!logger.IsEnabled(LogLevel.Debug)) return;
        //    LogSecurityTokenElementMetadata(logger, new SecurityTokenElementLogMessageState { Name = element.Name.LocalName, Namespace = element.Name.NamespaceName }, null);

        //    if (!logger.IsEnabled(LogLevel.Trace)) return;
        //    LogSecurityTokenValue(logger, element.ToString(), null);
        //};

        public static readonly Action<ILogger, SecurityTokenHandler> LogSecurityTokenHandlerValidationAttempt = (logger, handler) =>
        {
            if (!logger.IsEnabled(LogLevel.Debug)) return;

            var type = handler.GetType();
            LogSecurityTokenHandlerTypeValidationAttempt(logger, type.FullName, null);
        };

        public static readonly Action<ILogger, SecurityTokenHandler> LogSuccessfulSecurityTokenHandlerValidation = (logger, handler) =>
        {
            if (!logger.IsEnabled(LogLevel.Information)) return;

            var type = handler.GetType();
            LogSuccessfulSecurityTokenHandlerTypeValidation(logger, type.FullName, null);
        };

        public static readonly Action<ILogger, SecurityTokenHandler, Exception> LogFailedSecurityTokenHandlerValidation = (logger, handler, exception) =>
        {
            if (!logger.IsEnabled(LogLevel.Warning)) return;

            var type = handler.GetType();
            LogFailedSecurityTokenHandlerTypeValidation(logger, type.FullName, exception);
        };

        private static readonly Action<ILogger, string, Exception> LogSecurityTokenHandlerTypeValidationAttempt
            = LoggerMessage.Define<string>(LogLevel.Debug, 0, "Attempting to validate token using {fullname}");

        private static readonly Action<ILogger, string, Exception> LogSuccessfulSecurityTokenHandlerTypeValidation
            = LoggerMessage.Define<string>(LogLevel.Information, 0, "Successfully validated token using {fullname}");

        private static readonly Action<ILogger, string, Exception> LogFailedSecurityTokenHandlerTypeValidation
            = LoggerMessage.Define<string>(LogLevel.Warning, 0, "Failed validation of token using {fullname}");

        private static readonly Action<ILogger, string, Exception> LogTimestampElementValue
            = LoggerMessage.Define<string>(LogLevel.Trace, 0, "WS-Security timestamp element value" + Environment.NewLine + "{timestamp}");

        private static readonly Action<ILogger, string, Exception> LogSignatureElementValue
            = LoggerMessage.Define<string>(LogLevel.Trace, 0, "WS-Security signature element value" + Environment.NewLine + "{signature}");

        private static readonly Action<ILogger, SecurityTokenElementLogMessageState, Exception> LogSecurityTokenElementMetadata
            = LoggerMessage.Define<SecurityTokenElementLogMessageState>(LogLevel.Debug, 0, "WS-Security security token received" + Environment.NewLine + "{token}");

        private static readonly Action<ILogger, string, Exception> LogSecurityTokenValue 
            = LoggerMessage.Define<string>(LogLevel.Trace, 0, "WS-Security security token element value" + Environment.NewLine + "{value}");

        private static XmlReader CreateBufferedReader(XNode node) => XmlReader.Create(new MemoryStream(Encoding.UTF8.GetBytes(node.ToString(SaveOptions.DisableFormatting))));
    }
}
