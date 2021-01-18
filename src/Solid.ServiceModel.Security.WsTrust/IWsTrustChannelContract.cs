using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Solid.ServiceModel.Security
{
    /// <summary>
    /// The contract for performing WS-Trust requests.
    /// </summary>
    [ServiceContract]
    public interface IWsTrustChannelContract : IWsTrustContract
    {
        /// <summary>
        /// The cancel method.
        /// </summary>
        /// <param name="request">A <see cref="WsTrustRequest"/> instance.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="WsTrustResponse"/>.</returns>
        Task<WsTrustResponse> CancelAsync(WsTrustRequest request);

        /// <summary>
        /// The issue method.
        /// </summary>
        /// <param name="request">A <see cref="WsTrustRequest"/> instance.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="WsTrustResponse"/>.</returns>
        Task<WsTrustResponse> IssueAsync(WsTrustRequest request);

        /// <summary>
        /// The renew method.
        /// </summary>
        /// <param name="request">A <see cref="WsTrustRequest"/> instance.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="WsTrustResponse"/>.</returns>
        Task<WsTrustResponse> RenewAsync(WsTrustRequest request);

        /// <summary>
        /// The validate method.
        /// </summary>
        /// <param name="request">A <see cref="WsTrustRequest"/> instance.</param>
        /// <returns>A <see cref="Task{TResult}"/> of <see cref="WsTrustResponse"/>.</returns>
        Task<WsTrustResponse> ValidateAsync(WsTrustRequest request);
    }
}
