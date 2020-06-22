using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Solid.Identity.Tokens;
using Solid.Identity.Protocols.WsTrust;
using Solid.Identity.Protocols.WsTrust.Exceptions;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Protocols.WsTrust
{
    public abstract class SecurityTokenService
    {
        protected WsTrustConstants Constants { get; private set; }
        public SecurityTokenHandlerProvider SecurityTokenHandlerProvider { get; }
        public WsTrustOptions Options { get; }
        public ISystemClock SystemClock { get; }

        protected SecurityTokenService(SecurityTokenHandlerProvider securityTokenHandlerProvider, IOptions<WsTrustOptions> options, ISystemClock systemClock)
        {
            SecurityTokenHandlerProvider = securityTokenHandlerProvider;
            Options = options.Value;
            SystemClock = systemClock;
        }

        public virtual async ValueTask<WsTrustResponse> IssueAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken)
        {
            await ValidateRequestAsync(request, cancellationToken);
            var scope = await GetScopeAsync(principal, request, cancellationToken);
            if (scope == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID2013"));

            var descriptor = await CreateSecurityTokenDescriptorAsync(request, scope);
            if (descriptor == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID2003"));
            if (descriptor.SigningCredentials == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID2079"));

            if(scope.TokenEncryptionRequired && descriptor.EncryptingCredentials == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID4184"));

            var handler = await GetSecurityTokenHandlerAsync(descriptor.TokenType, cancellationToken);
            if (handler == null)
                throw new NotSupportedException(ErrorMessages.GetFormattedMessage("ID4010", descriptor.TokenType));

            descriptor.Subject = await CreateOutgoingSubjectAsync(principal, request, cancellationToken);

            var token = handler.CreateToken(descriptor);
            descriptor.Token = token;
            //descriptor.TokenElement = GetTokenElement(token, handler);
            //descriptor.AttachedReference = new SecurityTokenReference
            //{
            //    Id = token.Id,
            //    TokenType = descriptor.TokenType,
            //    KeyIdentifier = 
            //};
            //descriptor.UnattachedReference = handler.CreateSecurityTokenReference(descriptor.Token, false);

            return await CreateResponseAsync(request, descriptor, cancellationToken);
        }

        public virtual ValueTask<WsTrustResponse> RenewAsync(ClaimsPrincipal principa, WsTrustRequest request, CancellationToken cancellationToken) 
            => throw new InvalidRequestException(ErrorMessages.ID3141, (request != null && request.RequestType != null ? request.RequestType : "Renew"));

        public virtual ValueTask<WsTrustResponse> CancelAsync(ClaimsPrincipal principa, WsTrustRequest request, CancellationToken cancellationToken)
            => throw new InvalidRequestException(ErrorMessages.ID3141, (request != null && request.RequestType != null ? request.RequestType : "Cancel"));

        public virtual ValueTask<WsTrustResponse> ValidateAsync(ClaimsPrincipal principa, WsTrustRequest request, CancellationToken cancellationToken)
            => throw new InvalidRequestException(ErrorMessages.ID3141, (request != null && request.RequestType != null ? request.RequestType : "Validate"));

        protected virtual ValueTask<WsTrustResponse> CreateResponseAsync(WsTrustRequest request, RequestedSecurityTokenDescriptor descriptor, CancellationToken cancellationToken)
        {
            if (descriptor == null) return new ValueTask<WsTrustResponse>();

            var response = new RequestSecurityTokenResponse();

            descriptor.ApplyTo(response);

            if (!string.IsNullOrEmpty(request.Context))
                response.Context = request.Context;

            if (!string.IsNullOrEmpty(request.KeyType))
                response.KeyType = request.KeyType;

            if (request.KeySizeInBits > 0 && IsSupportedAsymmetricKeyType(request.KeyType))
                response.KeySizeInBits = request.KeySizeInBits;

            // no replyto
            //if (request.ReplyTo != null)
            //    response.ReplyTo = descriptor.ReplyToAddress;

            if (!string.IsNullOrEmpty(descriptor.Audience))
                response.AppliesTo = new AppliesTo(new EndpointReference(descriptor.Audience));

            return new ValueTask<WsTrustResponse>(new WsTrustResponse(response));
        }

        protected virtual ValueTask<SecurityTokenHandler> GetSecurityTokenHandlerAsync(string tokenType, CancellationToken cancellationToken)
        {
            var handler = SecurityTokenHandlerProvider.GetSecurityTokenHandler(tokenType);
            return new ValueTask<SecurityTokenHandler>(handler);
        }

        protected virtual ValueTask<RequestedSecurityTokenDescriptor> CreateSecurityTokenDescriptorAsync(WsTrustRequest request, Scope scope)
        {
            var lifetime = GetTokenLifetime(request?.Lifetime);
            var descriptor = new RequestedSecurityTokenDescriptor
            {
                IssuedAt = lifetime.Created,
                NotBefore = lifetime.Created,
                Expires = lifetime.Expires,
                Issuer = Options.Issuer,
                SigningCredentials = CreateSigningCredentials(scope.SigningKey, scope.SigningAlgorithm ?? Options.DefaultSigningAlgorithm) ?? CreateSigningCredentials(Options.DefaultSigningKey, Options.DefaultSigningAlgorithm),
                EncryptingCredentials = CreateEncryptingCredentials(scope.EncryptingKey, scope.EncryptingAlgorithm),
                TokenType = request?.TokenType ?? Options.DefaultTokenType
            };

            return new ValueTask<RequestedSecurityTokenDescriptor>(descriptor);
        }

        protected virtual SigningCredentials CreateSigningCredentials(SecurityKey key, SecurityAlgorithm algorithm)
        {
            if (key == null) return null;
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (algorithm.Algorithm == null) throw new ArgumentNullException(nameof(algorithm.Algorithm));
            if (string.IsNullOrEmpty(algorithm.Digest)) return new SigningCredentials(key, algorithm.Algorithm);
            return new SigningCredentials(key, algorithm.Algorithm, algorithm.Digest);
        }

        protected virtual EncryptingCredentials CreateEncryptingCredentials(SecurityKey key, SecurityAlgorithm algorithm)
        {
            if (key == null) return null;
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (algorithm.Algorithm == null) throw new ArgumentNullException(nameof(algorithm.Algorithm));
            if (key is SymmetricSecurityKey symmetric) return new EncryptingCredentials(symmetric, algorithm.Algorithm);
            if (algorithm.Digest == null) throw new ArgumentNullException(nameof(algorithm.Digest));
            return new EncryptingCredentials(key, algorithm.Algorithm, algorithm.Digest);
        }

        protected virtual ValueTask ValidateRequestAsync(WsTrustRequest request, CancellationToken cancellationToken)
        {
            // currently we only support RST/RSTR pattern
            if (request == null)
                throw new InvalidRequestException("ID2051");

            //// STS only support Issue for now
            //if (request.RequestType != null && request.RequestType != RequestTypes.Issue)
            //{
            //    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidRequestException(SR.GetString(SR.ID2052)));
            //}

            // key type must be one of the supported types
            if (request.KeyType != null && !IsSupportedKeyType(request.KeyType))
                throw new InvalidRequestException("ID2053");

            // if key type is bearer key, we should fault if the KeySize element is present and its value is not equal to zero.
            if (StringComparer.Ordinal.Equals(request.KeyType, Constants.WsTrustKeyTypes.Bearer) && request.KeySizeInBits.HasValue && (request.KeySizeInBits.Value != 0))
                throw new InvalidRequestException("ID2050");

            //// token type must be supported for this STS
            //if (GetSecurityTokenHandler(request.TokenType) == null)
            //{
            //    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new UnsupportedTokenTypeBadRequestException(request.TokenType));
            //}

            request.KeyType = (string.IsNullOrEmpty(request.KeyType)) ? Constants.WsTrustKeyTypes.Symmetric : request.KeyType;

            if (request.KeyType.Equals(Constants.WsTrustKeyTypes.Symmetric, StringComparison.OrdinalIgnoreCase))
            {
                //
                // Check if the key size is within certain limit to prevent Dos attack
                //
                if (!request.KeySizeInBits.HasValue)
                    request.KeySizeInBits = Options.DefaultSymmetricKeySizeInBits;

                if (request.KeySizeInBits > Options.DefaultMaxSymmetricKeySizeInBits)
                    throw new InvalidRequestException("ID2056", request.KeySizeInBits.Value, Options.DefaultMaxSymmetricKeySizeInBits);
            }
            return new ValueTask();
        }

        protected abstract ValueTask<Scope> GetScopeAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken);

        protected abstract ValueTask<ClaimsIdentity> CreateOutgoingSubjectAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken);

        /// <summary>
        /// Gets the lifetime of the issued token.
        /// Normally called with the lifetime that arrived in the RST.  
        /// The algorithm for calculating the token lifetime is:
        /// requestLifeTime (in)            LifeTime (returned)
        /// Created     Expires             Created             Expires
        /// null        null                DateTime.UtcNow     DateTime.UtcNow + SecurityTokenServiceConfiguration.DefaultTokenLifetime
        /// C           null                C                   C + SecurityTokenServiceConfiguration.DefaultTokenLifetime
        /// null        E                   DateTime.UtcNow     E
        /// C           E                   C                   E
        /// </summary>
        /// <param name="requestLifetime">The requestor's desired life time.</param>
        protected virtual Lifetime GetTokenLifetime(Lifetime requestLifetime)
        {
            DateTime created;
            DateTime expires;

            var now = SystemClock.UtcNow.UtcDateTime;

            if (requestLifetime == null)
            {
                created = now;
                expires = now.Add(Options.DefaultTokenLifetime);
            }
            else
            {
                if (requestLifetime.Created.HasValue)
                    created = requestLifetime.Created.Value;
                else
                    created = now;

                if (requestLifetime.Expires.HasValue)
                    expires = requestLifetime.Expires.Value;
                else
                    expires = now.Add(Options.DefaultTokenLifetime);
            }

            VerifyComputedLifetime(created, expires);

            return new Lifetime(created, expires);
        }

        protected virtual XmlElement GetTokenElement(SecurityToken token, SecurityTokenHandler handler)
        {
            var document = new XmlDocument();
            using (var writer = document.CreateNavigator().AppendChild())
                handler.WriteToken(writer, token);
            return document.FirstChild as XmlElement;
        }

        // TODO: options? SupportedKeyTypes?
        protected virtual bool IsSupportedKeyType(string keyType)
            => IsSupportedSymmetricKeyType(keyType) || IsSupportedBearerKeyType(keyType) || IsSupportedAsymmetricKeyType(keyType);

        protected virtual bool IsSupportedAsymmetricKeyType(string keyType)
            => StringComparer.Ordinal.Equals(keyType, MicrosoftKeyTypes.Asymmetric);

        protected virtual bool IsSupportedSymmetricKeyType(string keyType)
            => StringComparer.Ordinal.Equals(keyType, Constants.WsTrustKeyTypes.Symmetric) || StringComparer.Ordinal.Equals(keyType, MicrosoftKeyTypes.Symmetric);

        protected virtual bool IsSupportedBearerKeyType(string keyType)
            => StringComparer.Ordinal.Equals(keyType, Constants.WsTrustKeyTypes.Bearer) || StringComparer.Ordinal.Equals(keyType, MicrosoftKeyTypes.Bearer);

        internal void Initialize(WsTrustConstants constants)
            => Constants = constants;

        private void VerifyComputedLifetime(DateTime created, DateTime expires)
        {
            var now = SystemClock.UtcNow.UtcDateTime;

            // if expires in past, throw
            if (DateTimeUtil.Add(DateTimeUtil.ToUniversalTime(expires), Options.MaxClockSkew) < now)
                throw new InvalidRequestException("ID2075", created, expires, now);

            // if creation time specified is greater than one day in future, throw
            if (DateTimeUtil.ToUniversalTime(created) > DateTimeUtil.Add(now + TimeSpan.FromDays(1), Options.MaxClockSkew))
                throw new InvalidRequestException("ID2076", created, expires, now);

            // if expiration time is equal to or before creation time, throw.  This would be hard to make happen as the Lifetime class checks this condition in the constructor
            if (expires <= created)
                throw new InvalidRequestException("ID2077", created, expires);

            // if timespan is greater than allowed, throw
            if ((expires - created) > Options.MaxTokenLifetime)
                throw new InvalidRequestException("ID2078", created, expires, Options.MaxTokenLifetime);
        }
    }
}
