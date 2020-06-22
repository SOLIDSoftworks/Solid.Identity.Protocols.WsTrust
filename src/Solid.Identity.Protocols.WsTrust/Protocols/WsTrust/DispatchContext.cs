using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading;

namespace Solid.Identity.Protocols.WsTrust
{
    public class DispatchContext
    {
        /// <summary>
        /// The identity of the requestor.
        /// </summary>
        public ClaimsPrincipal Principal { get; set; }

        /// <summary>
        /// The WS-Addressing action of the request message.
        /// </summary>
        public string RequestAction { get; set; }

        /// <summary>
        /// The request message.
        /// </summary>
        public WsTrustMessage RequestMessage { get; set; }

        /// <summary>
        /// The desired WS-Addressing action of the response message.
        /// </summary>
        public string ResponseAction { get; set; }

        /// <summary>
        /// The response message.
        /// </summary>
        public WsTrustResponse ResponseMessage { get; set; }

        /// <summary>
        /// The <see cref="SecurityTokenService"/> object which should process <see cref="RequestMessage"/>.
        /// </summary>
        public SecurityTokenService SecurityTokenService { get; set; }

        /// <summary>
        /// The WS-Trust namespace uri defining the schema for the request and response messages.
        /// </summary>
        public string TrustNamespace { get; set; }

        public MessageVersion MessageVersion { get; set; }

        public CancellationToken CancellationToken { get; set; }
    }
}
