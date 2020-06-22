using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    internal static class WsTrustServiceContractConstants
    {
        public const string ServiceBehaviorName = "SecurityTokenService";
        public const string Namespace = "http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice";

        public static class Contracts
        {
            public const string IWsTrustFeb2005Async = "IWSTrustFeb2005Async";
            public const string IWsTrustFeb2005Sync = "IWSTrustFeb2005Sync";
            public const string IWsTrust13Sync = "IWSTrust13Sync";
            public const string IWsTrust13Async = "IWSTrust13Async";
        }

        public static class Actions
        {
            public const string TrustFeb2005Cancel = "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel";
            public const string TrustFeb2005CancelRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Cancel";
            public const string TrustFeb2005CancelResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Cancel";
            public const string TrustFeb2005Issue = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
            public const string TrustFeb2005IssueRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
            public const string TrustFeb2005IssueResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue";
            public const string TrustFeb2005Renew = "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew";
            public const string TrustFeb2005RenewRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Renew";
            public const string TrustFeb2005RenewResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Renew";
            public const string TrustFeb2005Validate = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
            public const string TrustFeb2005ValidateRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Validate";
            public const string TrustFeb2005ValidateResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Validate";

            public const string Trust13Cancel = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel";
            public const string Trust13CancelRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Cancel";
            public const string Trust13CancelResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Cancel";
            public const string Trust13CancelFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/CancelFinal";
            public const string Trust13Issue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
            public const string Trust13IssueRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
            public const string Trust13IssueResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Issue";
            public const string Trust13IssueFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal";
            public const string Trust13Renew = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew";
            public const string Trust13RenewRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Renew";
            public const string Trust13RenewResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Renew";
            public const string Trust13RenewFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/RenewFinal";
            public const string Trust13Status = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
            public const string Trust13Validate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate";
            public const string Trust13ValidateRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate";
            public const string Trust13ValidateResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Validate";
            public const string Trust13ValidateFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/ValidateFinal";
        }

        public static class Operations
        {
            // IWSTrustFeb2005Async Operations.
            public const string TrustFeb2005CancelAsync = nameof(TrustFeb2005CancelAsync);
            public const string TrustFeb2005CancelResponseAsync = nameof(TrustFeb2005CancelResponseAsync);
            public const string TrustFeb2005IssueAsync = nameof(TrustFeb2005IssueAsync);
            public const string TrustFeb2005IssueResponseAsync = nameof(TrustFeb2005IssueResponseAsync);
            public const string TrustFeb2005RenewAsync = nameof(TrustFeb2005RenewAsync);
            public const string TrustFeb2005RenewResponseAsync = nameof(TrustFeb2005RenewResponseAsync);
            public const string TrustFeb2005ValidateAsync = nameof(TrustFeb2005ValidateAsync);
            public const string TrustFeb2005ValidateResponseAsync = nameof(TrustFeb2005ValidateResponseAsync);

            // IWSTrustFeb2005Sync Operations.
            public const string TrustFeb2005Cancel = nameof(TrustFeb2005Cancel);
            public const string TrustFeb2005CancelResponse = nameof(TrustFeb2005CancelResponse);
            public const string TrustFeb2005Issue = nameof(TrustFeb2005Issue);
            public const string TrustFeb2005IssueResponse = nameof(TrustFeb2005IssueResponse);
            public const string TrustFeb2005Renew = nameof(TrustFeb2005Renew);
            public const string TrustFeb2005RenewResponse = nameof(TrustFeb2005RenewResponse);
            public const string TrustFeb2005Validate = nameof(TrustFeb2005Validate);
            public const string TrustFeb2005ValidateResponse = nameof(TrustFeb2005ValidateResponse);

            // IWSTrust13Async Operations.
            public const string Trust13CancelAsync = nameof(Trust13CancelAsync);
            public const string Trust13CancelResponseAsync = nameof(Trust13CancelResponseAsync);
            public const string Trust13IssueAsync = nameof(Trust13IssueAsync);
            public const string Trust13IssueResponseAsync = nameof(Trust13IssueResponseAsync);
            public const string Trust13RenewAsync = nameof(Trust13RenewAsync);
            public const string Trust13RenewResponseAsync = nameof(Trust13RenewResponseAsync);
            public const string Trust13ValidateAsync = nameof(Trust13ValidateAsync);
            public const string Trust13ValidateResponseAsync = nameof(Trust13ValidateResponseAsync);

            // IWSTrust13Sync Operations.
            public const string Trust13Cancel = nameof(Trust13Cancel);
            public const string Trust13CancelResponse = nameof(Trust13CancelResponse);
            public const string Trust13Issue = nameof(Trust13Issue);
            public const string Trust13IssueResponse = nameof(Trust13IssueResponse);
            public const string Trust13Renew = nameof(Trust13Renew);
            public const string Trust13RenewResponse = nameof(Trust13RenewResponse);
            public const string Trust13Validate = nameof(Trust13Validate);
            public const string Trust13ValidateResponse = nameof(Trust13ValidateResponse);
        }
    }
}
