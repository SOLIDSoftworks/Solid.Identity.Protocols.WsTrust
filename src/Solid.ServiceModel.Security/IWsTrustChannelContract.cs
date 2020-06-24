using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Solid.ServiceModel.Security
{
    [ServiceContract]
    public interface IWsTrustChannelContract : IWsTrustContract
    {
        Task<WsTrustResponse> CancelAsync(WsTrustRequest request);
        Task<WsTrustResponse> IssueAsync(WsTrustRequest request);
        Task<WsTrustResponse> RenewAsync(WsTrustRequest request);
        Task<WsTrustResponse> ValidateAsync(WsTrustRequest request);
    }
}
