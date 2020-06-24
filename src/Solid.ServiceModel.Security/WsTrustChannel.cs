using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.ServiceModel.Security
{
    public class WsTrustChannel : IWsTrustChannelContract, IChannel
    {
        private MessageVersion _messageVersion;
        private WsTrustVersion _wsTrustVersion;
        private WsTrustConstants _wsTrustConstants;
        private IWsTrustChannelContract _contract;
        private IChannel _inner;

        public WsTrustChannel(WsTrustChannelFactory factory, IWsTrustChannelContract inner, WsTrustVersion version)
        {
            _wsTrustVersion = version;
            if (version == WsTrustVersion.TrustFeb2005)
                _wsTrustConstants = WsTrustConstants.TrustFeb2005;
            else if (version == WsTrustVersion.Trust13)
                _wsTrustConstants = WsTrustConstants.Trust13;
            else if (version == WsTrustVersion.Trust14)
                _wsTrustConstants = WsTrustConstants.Trust14;
            else
                throw new ArgumentException(nameof(version), $"Invalid {nameof(WsTrustVersion)}");

            _contract = inner;
            _inner = inner as IChannel;

            _messageVersion = factory.Endpoint?.Binding?.MessageVersion ?? MessageVersion.Default;
        }

        public Task<WsTrustResponse> CancelAsync(WsTrustRequest request)
            => PerformActionAsync(Operation.Cancel, request);

        public Task<Message> CancelAsync(Message message)
            => _contract.CancelAsync(message);

        public Task<WsTrustResponse> IssueAsync(WsTrustRequest request)
            => PerformActionAsync(Operation.Issue, request);

        public Task<Message> IssueAsync(Message message)
            => _contract.IssueAsync(message);

        public Task<WsTrustResponse> RenewAsync(WsTrustRequest request)
            => PerformActionAsync(Operation.Renew, request);

        public Task<Message> RenewAsync(Message message)
            => _contract.RenewAsync(message);

        public Task<WsTrustResponse> ValidateAsync(WsTrustRequest request)
            => PerformActionAsync(Operation.Validate, request);

        public Task<Message> ValidateAsync(Message message)
            => _contract.ValidateAsync(message);

        private async Task<WsTrustResponse> PerformActionAsync(Operation operation, WsTrustRequest request)
        {
            var requestMessage = SerializeMessage(operation, request);
            var responseMessage = null as Message;

            switch (operation)
            {
                case Operation.Cancel:
                    responseMessage = await CancelAsync(requestMessage);
                    break;
                case Operation.Issue:
                    responseMessage = await IssueAsync(requestMessage);
                    break;
                case Operation.Renew:
                    responseMessage = await RenewAsync(requestMessage);
                    break;
                case Operation.Validate:
                    responseMessage = await ValidateAsync(requestMessage);
                    break;
                default:
                    // TODO: get correct error message
                    throw new InvalidOperationException("ID3285");
            }

            return DeserializeResponse(responseMessage);
        }

        private WsTrustResponse DeserializeResponse(Message message)
        {
            var serializer = new WsTrustSerializer();
            using (var stream = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false))
                {
                    message.WriteMessage(writer);
                }
                stream.Position = 0;
                using (var reader = XmlDictionaryReader.CreateTextReader(stream, XmlDictionaryReaderQuotas.Max))
                {
                    return serializer.ReadResponse(reader);
                }
            }
        }

        private Message SerializeMessage(Operation operation, WsTrustRequest request)
        {
            var serializer = new WsTrustSerializer();
            using (var stream = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false))
                {
                    serializer.WriteRequest(writer, _wsTrustVersion, request);
                }
                stream.Position = 0;
                using (var reader = XmlReader.Create(stream))
                {
                    return Message.CreateMessage(_messageVersion, GetAction(operation), reader);
                }
            }
        }

        private string GetAction(Operation operation)
        {
            switch (operation)
            {
                case Operation.Cancel: return _wsTrustConstants.WsTrustActions.Cancel;
                case Operation.Issue: return _wsTrustConstants.WsTrustActions.Issue;
                case Operation.Renew: return _wsTrustConstants.WsTrustActions.Renew;
                case Operation.Validate: return _wsTrustConstants.WsTrustActions.Validate;
            }
            throw new InvalidOperationException("ID3285");
        }

        CommunicationState ICommunicationObject.State => _inner.State;

        event EventHandler ICommunicationObject.Closed
        {
            add => _inner.Closed += value;
            remove => _inner.Closed -= value;
        }

        event EventHandler ICommunicationObject.Closing
        {
            add => _inner.Closing += value;
            remove => _inner.Closing -= value;
        }

        event EventHandler ICommunicationObject.Faulted
        {
            add => _inner.Faulted += value;
            remove => _inner.Faulted -= value;
        }

        event EventHandler ICommunicationObject.Opened
        {
            add => _inner.Opened += value;
            remove => _inner.Opened -= value;
        }

        event EventHandler ICommunicationObject.Opening
        {
            add => _inner.Opening += value;
            remove => _inner.Opening -= value;
        }

        void ICommunicationObject.Abort() => _inner.Abort();

        IAsyncResult ICommunicationObject.BeginClose(AsyncCallback callback, object state) => _inner.BeginClose(callback, state);

        IAsyncResult ICommunicationObject.BeginClose(TimeSpan timeout, AsyncCallback callback, object state) => _inner.BeginClose(timeout, callback, state);

        IAsyncResult ICommunicationObject.BeginOpen(AsyncCallback callback, object state) => _inner.BeginOpen(callback, state);

        IAsyncResult ICommunicationObject.BeginOpen(TimeSpan timeout, AsyncCallback callback, object state) => _inner.BeginOpen(timeout, callback, state);

        void ICommunicationObject.Close() => _inner.Close();

        void ICommunicationObject.Close(TimeSpan timeout) => _inner.Close(timeout);

        void ICommunicationObject.EndClose(IAsyncResult result) => _inner.EndClose(result);

        void ICommunicationObject.EndOpen(IAsyncResult result) => _inner.EndOpen(result);

        T IChannel.GetProperty<T>() => _inner.GetProperty<T>();

        void ICommunicationObject.Open() => _inner.Open();

        void ICommunicationObject.Open(TimeSpan timeout) => _inner.Open(timeout);

        enum Operation
        {
            Cancel,
            Issue,
            Renew,
            Validate
        }
    }
}
