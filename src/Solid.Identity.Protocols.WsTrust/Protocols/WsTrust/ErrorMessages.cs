using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    internal static class ErrorMessages
    {
        public static IReadOnlyDictionary<string, string> Messages;
        static ErrorMessages()
        {
            var dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { ID0023, "Failed to create an instance of '{0}' from configuration. A custom configuration element was specified, but the method LoadCustomConfiguration was not implemented. Override LoadCustomConfiguration to handle custom configuration loading." },
                { ID0020, "The collection is empty." },
                { ID3285, "The WS-Trust operation '{0}' is not valid or unsupported." },
                { ID3287, "WSTrustChannelFactory does not support changing the value of this property after a channel is created." },
                { ID3286, "The 'inner' parameter must implement the 'System.ServiceModel.Channels.IChannel' interface." },
                { ID3269, "Cannot determine the TrustVersion. It must either be specified explicitly, or a SecurityBindingElement must be present in the binding." },
                { ID3270, "The WSTrustChannel does not support multi-leg issuance protocols. The RSTR received from the STS must be enclosed in a RequestSecurityTokenResponseCollection element." },
                { ID3097, "ServiceHost does not contain any valid Endpoints. Add at least one valid endpoint in the SecurityTokenServiceConfiguration.TrustEndpoints collection." },
                { ID3023, "The WSTrustServiceContract only supports receiving RequestSecurityToken messages asynchronously. If you need to support more message types, override the WSTrustServiceContract.BeginDispatchRequest and EndDispatchRequest." },
                { ID3022, "The WSTrustServiceContract only supports receiving RequestSecurityToken messages. If you need to support more message types, override the WSTrustServiceContract.DispatchRequest method." },
                { ID3002, "WSTrustServiceContract could not create a SecurityTokenService instance from WSTrustServiceContract.SecurityTokenServiceConfiguration." },
                { ID3004, "Cannot obtain the schema for namespace: '{0}'." },
                { ID3193, "The WSTrustChannel cannot compute a proof key. The received RequestedSecurityTokenResponse indicates that the proof key is computed using combined entropy. However, the response does not include an entropy." },
                { ID3192, "The WSTrustChannel cannot compute a proof key. The received RequestedSecurityTokenResponse does not contain a RequestedProofToken and the ComputedKeyAlgorithm specified in the response is not supported: '{0}'." },
                { ID3191, "The WSTrustChannel received a RequestedSecurityTokenResponse message containing an Entropy without a ComputedKeyAlgorithm." },
                { ID3190, "The WSTrustChannel cannot compute a proof key without a valid SecurityToken set as the RequestSecurityToken.UseKey when the RequestSecurityToken.KeyType is '{0}'." },
                { ID3194, "The WSTrustChannel cannot compute a proof key. The received RequestedSecurityTokenResponse indicates that the proof key is computed using combined entropy. However, the request does not include an entropy." },
                { ID3139, "The WSTrustChannel cannot compute a proof key. The KeyType '{0}' is not supported. Valid proof key types supported by the WSTrustChannel are WSTrust13 and WSTrustFeb2005." },
                { ID3138, "The RequestSecurityTokenResponse that was received did not contain a SecurityToken." },
                { ID3137, "The TrustVersion '{0}', is not supported, only 'TrustVersion.WSTrust13' and 'TrustVersion.WSTrustFeb2005' is supported." },
                { ID3113, "The WSTrustServiceContract does not support receiving '{0}' messages with the '{1}' SOAP action. If you need to support this, override the ValidateDispatchContext method." },
                { ID3112, "Unrecognized RequestType '{0}' specified in the incoming request." },
                { ID3114, "The WSTrustService cannot deserialize the WS-Trust request." },
                { ID3148, "WsdlEndpointConversionContext.WsdlPort.Service.ServiceDescription cannot be null." },
                { ID3149, "Cannot find an input message type for PortType '({0}, {1})' for operation '{2}' in the given ServiceDescription." },
                { ID3146, "WsdlEndpointConversionContext.WsdlPort cannot be null." },
                { ID3147, "WsdlEndpointConversionContext.WsdlPort.Service cannot be null." },
                { ID3144, "The PortType '{0}' Operation '{1}' has Message '{2}' is expected to have only one part but contains '{3}'." },
                { ID3140, "Specify one or more BaseAddresses to enable metadata or set DisableWsdl to true in the SecurityTokenServiceConfiguration." },
                { ID3141, "The RequestType '{0}', is not supported. If you need to support this RequestType, override the corresponding virtual method in your SecurityTokenService derived class." },
                { ID3150, "Cannot find an output message type for PortType '({0}, {1})' for operation '{2}' in the given ServiceDescription." },
                { ID2004, "IAsyncResult must be the AsyncResult instance returned from the Begin call. The runtime is expecting '{0}', and the actual type is '{1}'." },
                { ID5004, "Unrecognized namespace: '{0}'." },
                { ID4053, "The token has WS-SecureConversation version '{0}'.  Version '{1}' was expected." },
                { ID4041, "Cannot configure the ServiceHost '{0}'. The ServiceHost is in a bad state and cannot be configured." },
                { ID4072, "The SecurityTokenHandler '{0}' registered for TokenType '{1}' must derive from '{2}'." },
                { ID4008, "'{0}' does not provide an implementation for '{1}'." },
                { ID4039, "A custom ServiceAuthorizationManager has been configured. Any custom ServiceAuthorizationManager must be derived from IdentityModelServiceAuthorizationManager." },
                { ID4287, "The SecurityTokenRequirement '{0}' doesn't contain a ListenUri." },
                { ID4285, "Cannot replace SecurityToken with Id '{0}' in cache with new one. Token must exist in cache to be replaced." },
                { ID4271, "No IAuthorizationPolicy was found for the Transport security token '{0}'." },
                { ID4274, "The Configuration property of this SecurityTokenHandler is set to null. Tokens cannot be read or validated in this state. Set this property or add this SecurityTokenHandler to a SecurityTokenHandlerCollection with a valid Configuration property." },
                { ID4268, "MergeClaims must have at least one identity that is not null." },
                { ID4240, "The tokenRequirement must derived from 'RecipientServiceModelSecurityTokenRequirement' for SecureConversationSecurityTokens. The tokenRequirement is of type '{0}'." },
                { ID4244, "Internal error: sessionAuthenticator must support IIssuanceSecurityTokenAuthenticator." },
                { ID4245, "Internal error: sessionAuthenticator must support ICommunicationObject." },
                { ID4192, "The reader is not positioned on a KeyInfo element that can be read." },
                { ID4101, "The token cannot be validated because it is not a SamlSecurityToken or a Saml2SecurityToken. Token type: '{0}'" }
            };
            Messages = new ReadOnlyDictionary<string, string>(dictionary);
        }

        public static string GetFormattedMessage(string key, params object[] args)
        {
            if (!Messages.TryGetValue(key, out string message))
            {
                if (!args.Any()) 
                    return key;

                return $"{key}: {string.Join(", ", args.Select(o => o?.ToString()))}";
            }

            if (!args.Any()) 
                return $"{key}: {message}";

            return $"{key}: {string.Format(message, args)}";
        }

        public static readonly string ID0023 = nameof(ID0023);
        public static readonly string ID0020 = nameof(ID0020);
        public static readonly string ID3285 = nameof(ID3285);
        public static readonly string ID3287 = nameof(ID3287);
        public static readonly string ID3286 = nameof(ID3286);
        public static readonly string ID3269 = nameof(ID3269);
        public static readonly string ID3270 = nameof(ID3270);
        public static readonly string ID3097 = nameof(ID3097);
        public static readonly string ID3023 = nameof(ID3023);
        public static readonly string ID3022 = nameof(ID3022);
        public static readonly string ID3002 = nameof(ID3002);
        public static readonly string ID3004 = nameof(ID3004);
        public static readonly string ID3193 = nameof(ID3193);
        public static readonly string ID3192 = nameof(ID3192);
        public static readonly string ID3191 = nameof(ID3191);
        public static readonly string ID3190 = nameof(ID3190);
        public static readonly string ID3194 = nameof(ID3194);
        public static readonly string ID3139 = nameof(ID3139);
        public static readonly string ID3138 = nameof(ID3138);
        public static readonly string ID3137 = nameof(ID3137);
        public static readonly string ID3113 = nameof(ID3113);
        public static readonly string ID3112 = nameof(ID3112);
        public static readonly string ID3114 = nameof(ID3114);
        public static readonly string ID3148 = nameof(ID3148);
        public static readonly string ID3149 = nameof(ID3149);
        public static readonly string ID3146 = nameof(ID3146);
        public static readonly string ID3147 = nameof(ID3147);
        public static readonly string ID3144 = nameof(ID3144);
        public static readonly string ID3140 = nameof(ID3140);
        public static readonly string ID3141 = nameof(ID3141);
        public static readonly string ID3150 = nameof(ID3150);
        public static readonly string ID2004 = nameof(ID2004);
        public static readonly string ID5004 = nameof(ID5004);
        public static readonly string ID4053 = nameof(ID4053);
        public static readonly string ID4041 = nameof(ID4041);
        public static readonly string ID4072 = nameof(ID4072);
        public static readonly string ID4008 = nameof(ID4008);
        public static readonly string ID4039 = nameof(ID4039);
        public static readonly string ID4287 = nameof(ID4287);
        public static readonly string ID4285 = nameof(ID4285);
        public static readonly string ID4271 = nameof(ID4271);
        public static readonly string ID4274 = nameof(ID4274);
        public static readonly string ID4268 = nameof(ID4268);
        public static readonly string ID4240 = nameof(ID4240);
        public static readonly string ID4244 = nameof(ID4244);
        public static readonly string ID4245 = nameof(ID4245);
        public static readonly string ID4192 = nameof(ID4192);
        public static readonly string ID4101 = nameof(ID4101);
    }
}
