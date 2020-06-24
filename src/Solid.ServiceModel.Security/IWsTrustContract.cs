using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace Solid.ServiceModel.Security
{
    [ServiceContract]
    public interface IWsTrustContract
    {
        [OperationContract(Name = "Cancel", Action = "*", ReplyAction = "*")]
        Task<Message> CancelAsync(Message message);
        [OperationContract(Name = "Issue", Action = "*", ReplyAction = "*")]
        Task<Message> IssueAsync(Message message);
        [OperationContract(Name = "Renew", Action = "*", ReplyAction = "*")]
        Task<Message> RenewAsync(Message message);
        [OperationContract(Name = "Validate", Action = "*", ReplyAction = "*")]
        Task<Message> ValidateAsync(Message message);

    }
}
