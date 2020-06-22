using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.WsTrust13
{
    [ServiceContract(Name = WsTrustServiceContractConstants.Contracts.IWsTrust13Async, Namespace = WsTrustServiceContractConstants.Namespace)]
    public interface IWsTrust13AsyncContract
    {
        /// <summary>
        /// Definiton of Async RST/Cancel method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <returns>IAsyncResult result instance.</returns>
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13CancelAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13CancelRequest, ReplyAction = WsTrustServiceContractConstants.Actions.Trust13CancelFinal)]
        Task<Message> Trust13CancelAsync(Message request);

        /// <summary>
        /// Definiton of Async RST/Issue method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <returns>IAsyncResult result instance.</returns>
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13IssueAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13IssueRequest, ReplyAction = WsTrustServiceContractConstants.Actions.Trust13IssueFinal)]
        Task<Message> Trust13IssueAsync(Message request);

        /// <summary>
        /// Definiton of Async RST/Renew method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <returns>IAsyncResult result instance.</returns>
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13RenewAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13RenewRequest, ReplyAction = WsTrustServiceContractConstants.Actions.Trust13RenewFinal)]
        Task<Message> Trust13RenewAsync(Message request);


        /// <summary>
        /// Definiton of Async RST/Validate method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <returns>IAsyncResult result instance.</returns>
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13ValidateAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13ValidateRequest, ReplyAction = WsTrustServiceContractConstants.Actions.Trust13ValidateFinal)]
        Task<Message> Trust13ValidateAsync(Message request);

        /// <summary>
        /// Definiton of Async RSTR/Cancel method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <returns>IAsyncResult result instance.</returns>
        //
        // NOTE:
        //      ReplyAction = "*" has a side effect of not generating this operation, port, or messages in the 
        //      WCF-generated WSDL. This is desired.
        //
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13CancelResponseAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13CancelResponse, ReplyAction = "*")]
        Task<Message> Trust13CancelResponseAsync(Message request);


        /// <summary>
        /// Definiton of Async RSTR/Issue method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <returns>IAsyncResult result instance.</returns>
        //
        // NOTE:
        //      ReplyAction = "*" has a side effect of not generating this operation, port, or messages in the 
        //      WCF-generated WSDL. This is desired.
        //
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13IssueResponseAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13IssueResponse, ReplyAction = "*")]
        Task<Message> Trust13IssueResponseAsync(Message request);

        /// <summary>
        /// Definiton of Async RSTR/Renew method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <param name="callback">AsyncCallback context.</param>
        /// <param name="state">Asyn state.</param>
        /// <returns>IAsyncResult result instance.</returns>
        //
        // NOTE:
        //      ReplyAction = "*" has a side effect of not generating this operation, port, or messages in the 
        //      WCF-generated WSDL. This is desired.
        //
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13RenewResponseAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13RenewResponse, ReplyAction = "*")]
        Task<Message> Trust13RenewResponseAsync(Message request);

        /// <summary>
        /// Definiton of Async RSTR/Validate method for WS-Trust 1.3
        /// </summary>
        /// <param name="request">Request Message containing the RST.</param>
        /// <param name="callback">AsyncCallback context.</param>
        /// <param name="state">Asyn state.</param>
        /// <returns>IAsyncResult result instance.</returns>
        //
        // NOTE:
        //      ReplyAction = "*" has a side effect of not generating this operation, port, or messages in the 
        //      WCF-generated WSDL. This is desired.
        //
        [OperationContract(Name = WsTrustServiceContractConstants.Operations.Trust13ValidateResponseAsync, AsyncPattern = true, Action = WsTrustServiceContractConstants.Actions.Trust13ValidateResponse, ReplyAction = "*")]
        Task<Message> Trust13ValidateResponseAsync(Message request);
    }
}
