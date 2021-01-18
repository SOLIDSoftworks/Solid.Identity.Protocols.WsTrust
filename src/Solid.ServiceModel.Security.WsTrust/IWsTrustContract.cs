using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace Solid.ServiceModel.Security
{
    /// <summary>
    /// The base contract for performing WS-Trust requests.
    /// </summary>
    [ServiceContract]    
    public interface IWsTrustContract
    {
        /// <summary>
        /// The base cancel method.
        /// </summary>
        /// <param name="message">The request message.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="Message"/>.</returns>
        [OperationContract(Name = "Cancel", Action = "*", ReplyAction = "*")]
        Task<Message> CancelAsync(Message message);

        /// <summary>
        /// The base issue method.
        /// </summary>
        /// <param name="message">The request message.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="Message"/>.</returns>
        [OperationContract(Name = "Issue", Action = "*", ReplyAction = "*")]
        Task<Message> IssueAsync(Message message);

        /// <summary>
        /// The base renew method.
        /// </summary>
        /// <param name="message">The request message.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="Message"/>.</returns>
        [OperationContract(Name = "Renew", Action = "*", ReplyAction = "*")]
        Task<Message> RenewAsync(Message message);

        /// <summary>
        /// The base validate method.
        /// </summary>
        /// <param name="message">The request message.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="Message"/>.</returns>
        [OperationContract(Name = "Validate", Action = "*", ReplyAction = "*")]
        Task<Message> ValidateAsync(Message message);
    }
}
