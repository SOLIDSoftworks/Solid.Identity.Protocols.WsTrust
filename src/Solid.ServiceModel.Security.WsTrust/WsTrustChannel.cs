using Solid.IdentityModel.Tokens.Xml;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.ServiceModel.Security
{
    internal class WsTrustChannel : WsTrustChannelBase, IWsTrustChannelContract
    {
        private WsTrustVersion _version;
        private WsTrustConstants _constants;
        private MessageVersion _messageVersion;
        private IWsTrustContract _contract;
        private WsTrustSerializer _serializer;

        public WsTrustChannel(WsTrustVersion version, IWsTrustContract contract, WsTrustSerializer serializer)
            : base(contract as IChannel)
        {
            // TODO: add null guards
            _version = version;
            _constants = GetConstants(version);
            // TODO: get message version from binding
            _messageVersion = MessageVersion.Default;
            _contract = contract;

            _serializer = serializer;
        }

        public async Task<WsTrustResponse> CancelAsync(WsTrustRequest request)
        {
            var requestMessage = CreateMessage(request, _constants.WsTrustActions.CancelRequest);
            var responseMessage = await CancelAsync(requestMessage);
            return ReadResponse(responseMessage);
        }

        public async Task<WsTrustResponse> IssueAsync(WsTrustRequest request)
        {
            var requestMessage = CreateMessage(request, _constants.WsTrustActions.IssueRequest);
            var responseMessage = await IssueAsync(requestMessage);
            return ReadResponse(responseMessage);
        }

        public async Task<WsTrustResponse> RenewAsync(WsTrustRequest request)
        {
            var requestMessage = CreateMessage(request, _constants.WsTrustActions.RenewRequest);
            var responseMessage = await RenewAsync(requestMessage);
            return ReadResponse(responseMessage);
        }

        public async Task<WsTrustResponse> ValidateAsync(WsTrustRequest request)
        {
            var requestMessage = CreateMessage(request, _constants.WsTrustActions.ValidateRequest);
            var responseMessage = await ValidateAsync(requestMessage);
            return ReadResponse(responseMessage);
        }

        public Task<Message> CancelAsync(Message message) => _contract.CancelAsync(message);

        public Task<Message> IssueAsync(Message message) => _contract.IssueAsync(message);

        public Task<Message> RenewAsync(Message message) => _contract.RenewAsync(message);

        public Task<Message> ValidateAsync(Message message) => _contract.ValidateAsync(message);

        protected virtual WsTrustResponse ReadResponse(Message message)
        {
            if(message.IsFault)
            {
                // TODO: Create constant for FaultMaxBufferSize
                var fault = MessageFault.CreateFault(message, 20 * 1024);
                var action = message.Headers?.Action;
                var exception = FaultException.CreateFault(fault, action);
                // TODO: add tracing
                throw exception;
            }

            var response = null as WsTrustResponse;
            using (var reader = message.GetReaderAtBodyContents())
                response = _serializer.ReadResponse(reader);

            foreach (var rstr in response.RequestSecurityTokenResponseCollection)
            {
                var element = rstr.RequestedSecurityToken?.TokenElement;
                if (element == null) continue;
                var created = rstr.Lifetime?.Created ?? DateTime.UtcNow;
                var expires = rstr.Lifetime?.Expires ?? DateTime.UtcNow.AddMinutes(5);
                var proof = null as SecurityKey;
                var internalTokenReference = null as GenericXmlSecurityKeyIdentifierClause;
                var externalTokenReference = null as GenericXmlSecurityKeyIdentifierClause;
                if (rstr.RequestedProofToken != null)
                {
                    if (rstr.RequestedProofToken.BinarySecret != null)
                        proof = new SymmetricSecurityKey(rstr.RequestedProofToken.BinarySecret.Data);
                }
                if (rstr.AttachedReference != null)
                    internalTokenReference = CreateKeyIdentifierClause(rstr.AttachedReference, true);
                if (rstr.UnattachedReference != null)
                    externalTokenReference = CreateKeyIdentifierClause(rstr.UnattachedReference, false);

                rstr.RequestedSecurityToken.SecurityToken = new GenericXmlSecurityToken(
                    element, 
                    created, 
                    expires, 
                    securityKey: proof, 
                    internalTokenReference: internalTokenReference,
                    externalTokenReference: externalTokenReference
                );
            }

            return response;
        }

        private GenericXmlSecurityKeyIdentifierClause CreateKeyIdentifierClause(SecurityTokenReference reference, bool attached)
        {
            var document = XmlHelper.CreateElement(writer => WriteSecurityTokenReference(writer, reference, attached));
            if (document == null) return null;
            return new GenericXmlSecurityKeyIdentifierClause(reference.KeyIdentifier.Id ?? reference.KeyIdentifier.Value, document.FirstChild as XmlElement);
        }

        private Message CreateMessage(WsTrustRequest request, string action) 
            => Message.CreateMessage(_messageVersion, action, new WsTrustRequestBodyWriter(_version, _serializer, request));

        private static WsTrustConstants GetConstants(WsTrustVersion version)
        {
            if (version == WsTrustVersion.TrustFeb2005) return WsTrustConstants.TrustFeb2005;
            if (version == WsTrustVersion.Trust13) return WsTrustConstants.Trust13;
            if (version == WsTrustVersion.Trust14) return WsTrustConstants.Trust14;

            throw new ArgumentException("Invalid WS-Trust version", nameof(version));
        }

        private void WriteSecurityTokenReference(XmlDictionaryWriter writer, SecurityTokenReference reference, bool attached)
        {
            var context = new WsSerializationContext(_version);
            if (attached)
                WsTrustSerializer.WriteRequestedAttachedReference(writer, context, reference);
            else
                WsTrustSerializer.WriteRequestedUnattachedReference(writer, context, reference);
        }
    }
}
