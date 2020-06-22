using Microsoft.IdentityModel.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.WsTrust13;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust
{
    public partial class WsTrustService : IWsTrust13AsyncContract, IWsTrust13SyncContract
    {
        public Task<Message> Trust13CancelAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.CancelRequest,
                WsTrustConstants.Trust13.WsTrustActions.CancelFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;

        public Task<Message> Trust13CancelResponseAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.CancelResponse,
                WsTrustConstants.Trust13.WsTrustActions.CancelFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;

        public Task<Message> Trust13IssueAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.IssueRequest,
                WsTrustConstants.Trust13.WsTrustActions.IssueFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;

        public Task<Message> Trust13IssueResponseAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.IssueResponse,
                WsTrustConstants.Trust13.WsTrustActions.IssueFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;

        public Task<Message> Trust13RenewAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.RenewRequest,
                WsTrustConstants.Trust13.WsTrustActions.RenewFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;

        public Task<Message> Trust13RenewResponseAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.RenewResponse,
                WsTrustConstants.Trust13.WsTrustActions.RenewFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;

        public Task<Message> Trust13ValidateAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.ValidateRequest,
                WsTrustConstants.Trust13.WsTrustActions.ValidateFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;

        public Task<Message> Trust13ValidateResponseAsync(Message request)
            => ProcessCoreAsync(
                request,
                WsTrustConstants.Trust13.WsTrustActions.ValidateResponse,
                WsTrustConstants.Trust13.WsTrustActions.ValidateFinal,
                WsTrustVersion.Trust13)
               .AsTask()
        ;
    }
}
