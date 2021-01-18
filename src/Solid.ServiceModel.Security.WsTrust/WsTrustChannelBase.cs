using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;

namespace Solid.ServiceModel.Security
{
    internal abstract class WsTrustChannelBase : IChannel
    {
        private IChannel _channel;

        protected WsTrustChannelBase(IChannel inner)
        {
            _channel = inner;
        }

        CommunicationState ICommunicationObject.State => _channel.State;

        event EventHandler ICommunicationObject.Closed
        {
            add => _channel.Closed += value;
            remove => _channel.Closed += value;
        }

        event EventHandler ICommunicationObject.Closing
        {
            add => _channel.Closing += value;
            remove => _channel.Closing += value;
        }

        event EventHandler ICommunicationObject.Faulted
        {
            add => _channel.Faulted += value;
            remove => _channel.Faulted += value;
        }

        event EventHandler ICommunicationObject.Opened
        {
            add => _channel.Opened += value;
            remove => _channel.Opened += value;
        }

        event EventHandler ICommunicationObject.Opening
        {
            add => _channel.Opening += value;
            remove => _channel.Opening += value;
        }

        T IChannel.GetProperty<T>() => _channel.GetProperty<T>();

        void ICommunicationObject.Abort() => _channel.Abort();

        IAsyncResult ICommunicationObject.BeginClose(AsyncCallback callback, object state) => _channel.BeginClose(callback, state);

        IAsyncResult ICommunicationObject.BeginClose(TimeSpan timeout, AsyncCallback callback, object state) => _channel.BeginClose(timeout, callback, state);

        IAsyncResult ICommunicationObject.BeginOpen(AsyncCallback callback, object state) => _channel.BeginOpen(callback, state);

        IAsyncResult ICommunicationObject.BeginOpen(TimeSpan timeout, AsyncCallback callback, object state) => _channel.BeginOpen(timeout, callback, state);

        void ICommunicationObject.Close() => _channel.Close();

        void ICommunicationObject.Close(TimeSpan timeout) => _channel.Close(timeout);

        void ICommunicationObject.EndClose(IAsyncResult result) => _channel.EndClose(result);

        void ICommunicationObject.EndOpen(IAsyncResult result) => _channel.EndOpen(result);

        void ICommunicationObject.Open() => _channel.Open();

        void ICommunicationObject.Open(TimeSpan timeout) => _channel.Open(timeout);
    }
}
