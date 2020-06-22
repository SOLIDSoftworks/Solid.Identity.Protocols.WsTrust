using Microsoft.Extensions.Options;
using Solid.Extensions.AspNetCore.Soap;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.Exceptions;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Solid.Identity.Protocols.WsTrust.Logging;

namespace Solid.Identity.Protocols.WsTrust
{
    public partial class WsTrustService
    {
        private ILogger _logger;
        private SecurityTokenServiceFactory _stsFactory;
        private ISoapContextAccessor _soapContextAccessor;
        private WsTrustSerializerFactory _serializerFactory;
        private WsTrustOptions _options;

        public WsTrustService(
            ILogger<WsTrustService> logger,
            SecurityTokenServiceFactory stsFactory,
            ISoapContextAccessor soapContextAccessor,
            WsTrustSerializerFactory serializerFactory,
            IOptionsMonitor<WsTrustOptions> monitor
        ) : this(logger as ILogger, stsFactory, soapContextAccessor, serializerFactory, monitor) { }

        protected WsTrustService(
            ILogger logger,
            SecurityTokenServiceFactory stsFactory,
            ISoapContextAccessor soapContextAccessor,
            WsTrustSerializerFactory serializerFactory,
            IOptionsMonitor<WsTrustOptions> monitor
        )
        {
            _logger = logger;
            _stsFactory = stsFactory;
            _soapContextAccessor = soapContextAccessor;
            _serializerFactory = serializerFactory;
            _options = monitor.CurrentValue;
        }

        protected virtual async ValueTask<Message> ProcessCoreAsync(Message requestMessage, string requestAction, string responseAction, WsTrustVersion version)
        {
            var constants = GetWsTrustConstants(version);
            var trace = new WsTrustMessageInformation
            {
                RequestAction = requestAction,
                ResponseAction = responseAction,
                WsTrustVersion = version,
                TrustNamespace = constants.Namespace
            };
            WsTrustLogMessages.WsTrustMessage(_logger, trace, null);

            var context = await CreateDispatchContextAsync(requestMessage, requestAction, responseAction, constants);
            await ValidateDispatchContextAsync(context);
            await DispatchRequestAsync(context, constants);
            var serializer = _serializerFactory.Create();
            _logger.LogInformation($"Serializing response for '{responseAction}'.");
            var response = Message.CreateMessage(context.MessageVersion, context.ResponseAction, context.ResponseMessage, new WsTrustResponseObjectSerializer(version, serializer));
            return response;
        }

        protected virtual WsTrustConstants GetWsTrustConstants(WsTrustVersion version)
        {
            if (version == WsTrustVersion.TrustFeb2005) return WsTrustConstants.TrustFeb2005;
            if (version == WsTrustVersion.Trust13) return WsTrustConstants.Trust13;
            if (version == WsTrustVersion.Trust14) return WsTrustConstants.Trust14;

            throw new NotSupportedException("Trust version not supported.");
        }

        protected virtual ValueTask ValidateDispatchContextAsync(DispatchContext context)
        {
            return new ValueTask();
        }

        /// <summary>
        /// Processes a WS-Trust request message, and optionally determines the appropriate
        /// response message and the WS-Addressing action for the response message.
        /// </summary>
        /// <param name="dispatchContext">Defines the request parameters to process and exposes properties
        /// that determine the response message and action.</param>
        protected virtual async ValueTask DispatchRequestAsync(DispatchContext dispatchContext, WsTrustConstants constants)
        {
            var request = dispatchContext.RequestMessage as WsTrustRequest;
            var action = dispatchContext.RequestAction;
            var sts = dispatchContext.SecurityTokenService;

            if (request == null) throw new InvalidRequestException(ErrorMessages.ID3022);

            if (action == constants.WsTrustActions.CancelRequest)
                dispatchContext.ResponseMessage = await sts.CancelAsync(dispatchContext.Principal, request, dispatchContext.CancellationToken);
            else if (action == constants.WsTrustActions.IssueRequest)
                dispatchContext.ResponseMessage = await sts.IssueAsync(dispatchContext.Principal, request, dispatchContext.CancellationToken);
            else if (action == constants.WsTrustActions.RenewRequest)
                dispatchContext.ResponseMessage = await sts.RenewAsync(dispatchContext.Principal, request, dispatchContext.CancellationToken);
            else if (action == constants.WsTrustActions.ValidateRequest)
                dispatchContext.ResponseMessage = await sts.ValidateAsync(dispatchContext.Principal, request, dispatchContext.CancellationToken);
            else
                throw new InvalidRequestException(ErrorMessages.ID3112, request.RequestType);
        }

        protected virtual ValueTask<DispatchContext> CreateDispatchContextAsync(Message requestMessage, string requestAction, string responseAction, WsTrustConstants constants)
        {
            var serializer = _serializerFactory.Create();
            var soapContext = _soapContextAccessor.SoapContext;
            var context = new DispatchContext
            {
                Principal = soapContext.User,
                RequestAction = requestAction,
                ResponseAction = responseAction,
                TrustNamespace = constants.Namespace,
                SecurityTokenService = _stsFactory.Create(constants), 
                MessageVersion = soapContext.MessageVersion,
                CancellationToken = soapContext.CancellationToken
            };

            using(var reader = requestMessage.GetReaderAtBodyContents())
            {
                if (reader.IsStartElement(WsTrustElements.RequestSecurityToken, constants.Namespace))
                    context.RequestMessage = serializer.ReadRequest(reader);
                //else if (reader.IsStartElement(WsTrustElements.RequestSecurityTokenResponse))
                //    context.ResponseMessage = serializer.ReadResponse(reader);
                else
                    throw new InvalidRequestException(ErrorMessages.ID3114);
            }

            return new ValueTask<DispatchContext>(context);
        }
    }
}
