using Microsoft.IdentityModel.Protocols.WsSecurity;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.Text;

namespace Solid.Extensions.AspNetCore.Soap
{

    internal static class Solid_Extensions_AspNetCore_Soap_Extensions_WsSecurity_SoapContextExtensions_Faults
    {
        public static FaultException CreateUnsupportedSecurityTokenFault(this SoapContext context) => CreateFault("UnsupportedSecurityToken", "An unsupported token was provided", context);
        public static FaultException CreateUnsupportedAlgorithmFault(this SoapContext context) => CreateFault("UnsupportedAlgorithm", "An unsupported signature or encryption algorithm was used", context);
        public static FaultException CreateInvalidSecurityFault(this SoapContext context) => CreateFault("InvalidSecurity", "An error was discovered processing the <wsse:Security> header", context);
        public static FaultException CreateInvalidSecurityTokenFault(this SoapContext context) => CreateFault("InvalidSecurityToken", "An invalid security token was provided", context);
        public static FaultException CreateFailedAuthenticationFault(this SoapContext context) => CreateFault("FailedAuthentication", "The security token could not be authenticated or authorized", context);
        public static FaultException CreateFailedCheckFault(this SoapContext context) => CreateFault("FailedCheck", "The signature or decryption was invalid", context);
        public static FaultException CreateSecurityTokenUnavailableFault(this SoapContext context) => CreateFault("SecurityTokenUnavailable", "Referenced security token could not be retrieved", context);
        public static FaultException CreateMessageExpiredFault(this SoapContext context) => CreateFault("MessageExpired", "The message has expired", context);
        private static FaultException CreateFault(string code, string reason, SoapContext context)
        {
            var ns = WsSecurityConstants.WsSecurity10.Namespace;
            var version = context.MessageVersion;
            
            if (version.Envelope == EnvelopeVersion.Soap11)
                return new FaultException(
                    new FaultReason(reason),
                    new FaultCode(code, ns),
                    context.Request.Headers.Action
                );

            return new FaultException(
                new FaultReason(reason),
                new FaultCode("Sender", SoapConstants.Soap12.EnvelopeNamespace, new FaultCode(code, ns)),
                context.Request.Headers.Action
            );
        }
    }
}

