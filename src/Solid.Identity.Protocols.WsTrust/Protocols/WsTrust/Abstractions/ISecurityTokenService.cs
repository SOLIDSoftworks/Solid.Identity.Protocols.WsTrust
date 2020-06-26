using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Abstractions
{
    public interface ISecurityTokenService
    {
        ValueTask<WsTrustResponse> IssueAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken);       
        ValueTask<WsTrustResponse> RenewAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken);        
        ValueTask<WsTrustResponse> CancelAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken);        
        ValueTask<WsTrustResponse> ValidateAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken);
    }
}
