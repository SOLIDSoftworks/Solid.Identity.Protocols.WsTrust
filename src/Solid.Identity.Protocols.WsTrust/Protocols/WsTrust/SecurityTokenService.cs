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
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Microsoft.Extensions.Logging;
using Solid.Identity.Protocols.WsSecurity;
using System.Security;
using System.Linq;
using Solid.Identity.Protocols.WsTrust.Logging;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Protocols.XmlEnc;

namespace Solid.Identity.Protocols.WsTrust
{
    public class SecurityTokenService : ISecurityTokenService
    {
        protected WsTrustConstants Constants { get; private set; }
        protected RelyingPartyProvider RelyingParties { get; }
        protected IncomingClaimsMapper Mapper { get; }
        protected OutgoingSubjectFactory SubjectFactory { get; }
        protected SecurityTokenHandlerProvider SecurityTokenHandlerProvider { get; }
        protected IServiceProvider Services { get; }
        protected WsTrustOptions Options { get; }
        protected ISystemClock SystemClock { get; }
        protected ILogger Logger { get; }
        protected IdentityProviderProvider IdentityProviders { get; }

        public SecurityTokenService(
            IdentityProviderProvider identityProviders,
            RelyingPartyProvider relyingParties, 
            IncomingClaimsMapper mapper, 
            OutgoingSubjectFactory subjectFactory, 
            SecurityTokenHandlerProvider securityTokenHandlerProvider,
            IServiceProvider services, 
            ILoggerFactory loggerFactory,
            IOptions<WsTrustOptions> options, 
            ISystemClock systemClock)
        {
            Logger = loggerFactory.CreateLogger(GetType().FullName);

            IdentityProviders = identityProviders;
            RelyingParties = relyingParties;
            Mapper = mapper;
            SubjectFactory = subjectFactory;
            SecurityTokenHandlerProvider = securityTokenHandlerProvider;
            Services = services;
            Options = options.Value;
            SystemClock = systemClock;
        }

        public virtual async ValueTask<WsTrustResponse> IssueAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken)
        {
            // currently we only support RST/RSTR pattern
            if (request == null)
                throw new InvalidRequestException("ID2051");

            await ApplyDefaultIssueValuesAsync(request, cancellationToken);
            await ValidateRequestAsync(principal, request, cancellationToken);

            var party = await GetRelyingPartyAsync(request.AppliesTo, cancellationToken);
            if (party == null)
                throw new InvalidOperationException($"Relying party not found: {request.AppliesTo.EndpointReference.Uri}");

            await ValidateRelyingPartyAsync(principal, request, party, cancellationToken);

            var scope = await CreateScopeAsync(principal, request, party, cancellationToken);
            if (scope == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID2013"));

            if (!await scope.RelyingParty.AuthorizeAsync(Services, principal))
                throw new SecurityException($"User is not authorized to be issued a token for {scope.RelyingParty.AppliesTo}");

            var descriptor = await CreateSecurityTokenDescriptorAsync(request, scope, cancellationToken);
            if (descriptor == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID2003"));
            if (descriptor.SigningCredentials == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID2079"));

            if(scope.RelyingParty.RequiresEncryptedToken && descriptor.EncryptingCredentials == null)
                throw new InvalidOperationException(ErrorMessages.GetFormattedMessage("ID4184"));

            var handler = await GetSecurityTokenHandlerAsync(descriptor.TokenType, cancellationToken);
            if (handler == null)
                throw new NotSupportedException(ErrorMessages.GetFormattedMessage("ID4010", descriptor.TokenType));

            descriptor.Subject = await CreateOutgoingSubjectAsync(request, scope, cancellationToken);

            var token = await CreateSecurityTokenAsync(scope, request, descriptor, handler, cancellationToken);
            descriptor.Token = token;
            descriptor.TokenElement = token.ConvertToXmlElement(handler);

            return await CreateResponseAsync(request, descriptor, cancellationToken);
        }

        public virtual ValueTask<WsTrustResponse> RenewAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken) 
            => throw new InvalidRequestException(ErrorMessages.ID3141, (request != null && request.RequestType != null ? request.RequestType : "Renew"));

        public virtual ValueTask<WsTrustResponse> CancelAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken)
            => throw new InvalidRequestException(ErrorMessages.ID3141, (request != null && request.RequestType != null ? request.RequestType : "Cancel"));

        public virtual ValueTask<WsTrustResponse> ValidateAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken)
            => throw new InvalidRequestException(ErrorMessages.ID3141, (request != null && request.RequestType != null ? request.RequestType : "Validate"));
        
        protected virtual ValueTask<SecurityToken> CreateSecurityTokenAsync(Scope scope, WsTrustRequest request, WsTrustSecurityTokenDescriptor descriptor, SecurityTokenHandler handler, CancellationToken cancellationToken)
            => new ValueTask<SecurityToken>(handler.CreateToken(descriptor));

        protected virtual async ValueTask<WsTrustResponse> CreateResponseAsync(WsTrustRequest request, WsTrustSecurityTokenDescriptor descriptor, CancellationToken cancellationToken)
        {
            if (descriptor == null) return null;

            var response = new RequestSecurityTokenResponse();
            var handler = await GetSecurityTokenHandlerAsync(request.TokenType, cancellationToken);

            try
            {
                var attached = handler.CreateSecurityTokenReference(descriptor.Token, true);
                if (attached is WsSecuritySecurityKeyIdentifierClause attachedClause)
                    descriptor.AttachedReference = attachedClause.CreateReference();

                var unattached = handler.CreateSecurityTokenReference(descriptor.Token, false);
                if (unattached is WsSecuritySecurityKeyIdentifierClause unattachedClause)
                    descriptor.UnattachedReference = unattachedClause.CreateReference();
            }
            catch { }

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

            var proofToken = await CreateRequestedProofTokenAsync(descriptor, cancellationToken);
            if (proofToken != null)
                response.RequestedProofToken = proofToken;

            return new WsTrustResponse(response);
        }

        protected virtual ValueTask<RequestedProofToken> CreateRequestedProofTokenAsync(WsTrustSecurityTokenDescriptor descriptor, CancellationToken cancellationToken)
        {
            if (descriptor.ProofKey == null) return new ValueTask<RequestedProofToken>();
            if (!(descriptor.ProofKey is SymmetricSecurityKey symmetric)) throw new NotSupportedException($"Asymmetric proof keys not supported for now.");

            // The microsoft ws-trust serializer can't handle encrypted RequestedProofToken. Hard code unencrypted for now.
            var secret = new BinarySecret(symmetric.Key, Constants.WsTrustKeyTypes.Symmetric);
            return new ValueTask<RequestedProofToken>(new RequestedProofToken(secret));
        }

        private IDictionary<string, IRelyingParty> _cache = new Dictionary<string, IRelyingParty>();
        protected virtual async ValueTask<IRelyingParty> GetRelyingPartyAsync(AppliesTo appliesTo, CancellationToken cancellationToken)
        {
            if (appliesTo == null) return null;
            var id = appliesTo.EndpointReference.Uri;
            if (_cache.TryGetValue(id, out var party)) return party;
            var p = await RelyingParties.GetRelyingPartyAsync(appliesTo.EndpointReference.Uri);
            _cache.Add(id, p);
            return p;
        }

        protected virtual ValueTask<SecurityTokenHandler> GetSecurityTokenHandlerAsync(string tokenType, CancellationToken cancellationToken)
        {
            var handler = SecurityTokenHandlerProvider.GetSecurityTokenHandler(tokenType);
            return new ValueTask<SecurityTokenHandler>(handler);
        }

        protected virtual async ValueTask<WsTrustSecurityTokenDescriptor> CreateSecurityTokenDescriptorAsync(WsTrustRequest request, Scope scope, CancellationToken cancellationToken)
        {
            var lifetime = CreateTokenLifetime(request?.Lifetime, scope);
            var descriptor = new WsTrustSecurityTokenDescriptor
            {
                Audience = scope.RelyingParty.AppliesTo,
                IssuedAt = lifetime.Created,
                Expires = lifetime.Expires,
                Issuer = scope.RelyingParty.ExpectedIssuer ?? Options.Issuer,
                SigningCredentials = scope.SigningCredentials,
                EncryptingCredentials = scope.RelyingParty.RequiresEncryptedToken ? scope.EncryptingCredentials : null,
                ProofKeyEncryptingCredentials = scope.RelyingParty.RequiresEncryptedSymmetricKeys ? scope.EncryptingCredentials : null,
                TokenType = request.TokenType
            };

            if (lifetime.Created != null)
                descriptor.NotBefore = lifetime.Created.Value.Subtract(scope.RelyingParty.ClockSkew ?? Options.MaxClockSkew);
            
            var requestorProofEncryptingCredentials = await GetRequestorProofEncryptingCredentialsAsync(request, cancellationToken);
            if (requestorProofEncryptingCredentials != null)
                descriptor.ProofKeyEncryptingCredentials = requestorProofEncryptingCredentials;
            descriptor.ProofKey = await CreateProofKeyAsync(request, scope, descriptor, cancellationToken);

            return descriptor;
        }

        protected virtual async ValueTask<SecurityKey> CreateProofKeyAsync(WsTrustRequest request, Scope scope, WsTrustSecurityTokenDescriptor descriptor, CancellationToken cancellationToken)
        {
            var keyType = request.KeyType;

            // asymmetric and psha1
            // not supported at this moment
            if (keyType == Constants.WsTrustKeyTypes.PublicKey || keyType == Constants.WsTrustKeyTypes.PSHA1)
                throw new NotSupportedException($"Key type '{keyType}' not supported at this time.");

            if (keyType == Constants.WsTrustKeyTypes.Bearer)
                return null;

            // symmetric
            if (request.ComputedKeyAlgorithm != null && request.ComputedKeyAlgorithm != "http://schemas.microsoft.com/idfx/computedkeyalgorithm/psha1")
                throw new NotSupportedException($"Computed key algortihm '{request.ComputedKeyAlgorithm}' not supported at this time.");

            if (descriptor.ProofKeyEncryptingCredentials == null && scope.RelyingParty.RequiresEncryptedSymmetricKeys)
                throw new InvalidOperationException("Cannot created proof token with no encrypting credentials.");

            if (scope.EncryptingCredentials == null && scope.RelyingParty.RequiresEncryptedToken)
                throw new InvalidOperationException("Missing encrypting credentials.");

            return await CreateSymmetricProofKeyAsync(request.KeySizeInBits.Value);
        }

        protected virtual async ValueTask<SymmetricSecurityKey> CreateSymmetricProofKeyAsync(int keySizeInBits)
        {
            var keySizeInBytes = keySizeInBits / 8;
            var remainder = keySizeInBits % 8;
            if (keySizeInBytes <= 0)
                throw new ArgumentOutOfRangeException(nameof(keySizeInBits));
            if (remainder > 0)
                throw new ArgumentException("Argument must be divisible by 8.", nameof(keySizeInBits));

            using (var random = await CreateRandomNumberGeneratorAsync())
            {
                var key = new byte[keySizeInBytes];
                random.GetNonZeroBytes(key);
                return new SymmetricSecurityKey(key);
            }
        }

        protected virtual ValueTask<EncryptingCredentials> GetRequestorProofEncryptingCredentialsAsync(WsTrustRequest request, CancellationToken cancellationToken)
        {
            if (request.ProofEncryption == null)
                return new ValueTask<EncryptingCredentials>();

            throw new NotSupportedException("Requestor proof encryption not supported at this time.");
        }

        protected virtual ValueTask<SigningCredentials> CreateSigningCredentialsAsync(IRelyingParty party, CancellationToken cancellationToken)
        {
            var key = party.SigningKey;
            var method = party.SigningAlgorithm ?? Options.DefaultSigningAlgorithm;

            if (key == null)
            {
                key = Options.DefaultSigningKey;
                method = Options.DefaultSigningAlgorithm;
            }

            if (key == null) return new ValueTask<SigningCredentials>();

            var credentials = method.CreateCredentials(key);

            var information = new SigningCredentialsInformation
            {
                SecurityKeyName = (key is X509SecurityKey x509) ? x509.Certificate.Subject : key.KeyId,
                SecurityKeyType = key.GetType().Name,
                Algorithm = method.SignatureAlgortihm,
                Digest = method.DigestAlgorithm
            };
            WsTrustLogMessages.SigningCredentialsCreated(Logger, information, null);

            return new ValueTask<SigningCredentials>(credentials);
        }

        protected virtual ValueTask<EncryptingCredentials> CreateEncryptingCredentialsAsync(IRelyingParty party, CancellationToken cancellationToken)
        {
            if (!party.RequiresEncryptedToken && !party.RequiresEncryptedSymmetricKeys) return new ValueTask<EncryptingCredentials>();

            var key = party.EncryptingKey;
            var method = party.EncryptingAlgorithm ?? Options.DefaultEncryptionAlgorithm;

            if (key == null)
            {
                key = Options.DefaultSigningKey;
                method = Options.DefaultEncryptionAlgorithm;
            }

            if (key == null) return new ValueTask<EncryptingCredentials>();

            var credentials = method.CreateCredentials(key);

            var information = new EncryptingCredentialsInformation
            {
                SecurityKeyName = (key is X509SecurityKey x509) ? x509.Certificate.Subject : key.KeyId,
                SecurityKeyType = key.GetType().Name,
                DataEncryptionAlgorithm = method.EncryptionAlgorithm,
                KeyWrapAlgorithm = method.KeyWrapAlgorithm
            };
            WsTrustLogMessages.EncryptingCredentialsCreated(Logger, information, null);

            return new ValueTask<EncryptingCredentials>(credentials);
        }

        protected virtual async ValueTask ValidateIdentityProviderAsync(ClaimsPrincipal principal, WsTrustRequest request, IIdentityProvider identityProvider, CancellationToken cancellationToken)
        {
            if (identityProvider.RestrictRelyingParties)
            {
                var appliesTo = request.AppliesTo.EndpointReference.Uri;
                if (!identityProvider.AllowedRelyingParties.Contains(appliesTo))
                    throw new SecurityException($"Identity provider ({identityProvider.Id}) attempting to request token for: {appliesTo}");
            }
        }

        protected virtual async ValueTask ValidateRelyingPartyAsync(ClaimsPrincipal principal, WsTrustRequest request, IRelyingParty party, CancellationToken cancellationToken)
        {
            var issuer = principal.FindFirst(WsSecurityClaimTypes.Issuer)?.Value;
            var appliesTo = request.AppliesTo.EndpointReference.Uri;
            if (party.ValidateRequestedTokenType && !party.SupportedTokenTypes.Contains(request.TokenType))
                throw new SecurityException($"Identity provider ({issuer}) attempting to request a token type the relying party ({appliesTo}) doesn't support: {request.TokenType}");

            if (!await party.AuthorizeAsync(Services, principal))
                throw new SecurityException($"User is not authorized to be issued a token for {party.AppliesTo}");
        }

        protected virtual async ValueTask ValidateRequestAsync(ClaimsPrincipal principal, WsTrustRequest request, CancellationToken cancellationToken)
        {
            // TODO: add virtual methods for each validation so they can be overridden seperately

            var issuer = principal.FindFirst(WsSecurityClaimTypes.Issuer)?.Value;
            if (issuer != null)
            {
                var idp = await IdentityProviders.GetIdentityProviderAsync(issuer);
                if (idp == null)
                    throw new SecurityException($"Unknown token issuer for incoming token: {issuer}");
                await ValidateIdentityProviderAsync(principal, request, idp, cancellationToken);
            }

            // currently we only support RST/RSTR pattern
            if (request == null)
                throw new InvalidRequestException("ID2051");

            if(request.AppliesTo == null)
                throw new InvalidRequestException("AppliesTo not specified.");

            // STS only support Issue for now
            if (request.RequestType != null && request.RequestType != Constants.WsTrustActions.Issue)
                throw new InvalidRequestException("ID2052");

            // key type must be one of the supported types
            if (request.KeyType != null && !IsSupportedKeyType(request.KeyType))
                throw new InvalidRequestException("ID2053");

            // if key type is bearer key, we should fault if the KeySize element is present and its value is not equal to zero.
            if (StringComparer.Ordinal.Equals(request.KeyType, Constants.WsTrustKeyTypes.Bearer) && request.KeySizeInBits.HasValue && (request.KeySizeInBits.Value != 0))
                throw new InvalidRequestException("ID2050");

            if (request.TokenType == null)
                throw new InvalidRequestException("No token type requested.");

            // token type must be supported for this STS
            if (GetSecurityTokenHandlerAsync(request.TokenType, cancellationToken) == null)
                throw new UnsupportedTokenTypeBadRequestException(request.TokenType);

            if (!IsSupportedKeyType(request.KeyType))
                throw new InvalidRequestException($"Unsupported key type: {request.KeyType}");

            //
            // Check if the key size is within certain limit to prevent Dos attack
            //
            if (request.KeyType.Equals(Constants.WsTrustKeyTypes.Symmetric, StringComparison.OrdinalIgnoreCase) &&
                request.KeySizeInBits > Options.DefaultMaxSymmetricKeySizeInBits)
                throw new InvalidRequestException("ID2056", request.KeySizeInBits.Value, Options.DefaultMaxSymmetricKeySizeInBits);

            if (request.KeyType.Equals(Constants.WsTrustKeyTypes.PublicKey, StringComparison.OrdinalIgnoreCase) &&
                request.UseKey == null)
                throw new InvalidRequestException($"Asymmetric key type requires a UseKey.");
        }

        protected virtual async ValueTask<ClaimsIdentity> CreateOutgoingSubjectAsync(WsTrustRequest request, Scope scope, CancellationToken cancellationToken)
        {
            var subject = await SubjectFactory.CreateOutgoingSubjectAsync(scope.Subject, scope.RelyingParty, request.TokenType);
            return subject;
        }

        protected virtual async ValueTask<Scope> CreateScopeAsync(ClaimsPrincipal principal, WsTrustRequest request, IRelyingParty party, CancellationToken cancellationToken)
        {
            var identity = ClaimsPrincipal.PrimaryIdentitySelector(principal.Identities);
            var claims = await MapIncomingClaimsAsync(principal.Claims);
            var user = new ClaimsIdentity(claims, identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
            var scope = new Scope(user, party);

            scope.SigningCredentials = await CreateSigningCredentialsAsync(party, cancellationToken);   
            scope.EncryptingCredentials = await CreateEncryptingCredentialsAsync(party, cancellationToken);

            return scope;
        }

        protected virtual async ValueTask<IEnumerable<Claim>> MapIncomingClaimsAsync(IEnumerable<Claim> claims)
        {
            var list = claims.ToList();
            var mapped = await Mapper.MapIncomingClaimsAsync(list);
            return mapped;
        }

        /// <summary>
        /// Gets the lifetime of the issued token.
        /// Normally called with the lifetime that arrived in the RST.  
        /// The algorithm for calculating the token lifetime is:
        /// requestLifetime (in)            Lifetime (returned)
        /// Created     Expires             Created             Expires
        /// null        null                DateTime.UtcNow     DateTime.UtcNow + SecurityTokenServiceConfiguration.DefaultTokenLifetime
        /// C           null                C                   C + SecurityTokenServiceConfiguration.DefaultTokenLifetime
        /// null        E                   DateTime.UtcNow     E
        /// C           E                   C                   E
        /// </summary>
        /// <param name="requestLifetime">The requestor's desired life time.</param>
        protected virtual Lifetime CreateTokenLifetime(Lifetime requestLifetime, Scope scope)
        {
            DateTime created;
            DateTime expires;

            var now = SystemClock.UtcNow.UtcDateTime;
            var lifetime = scope.RelyingParty.TokenLifetime ?? Options.DefaultTokenLifetime; 

            if (requestLifetime == null)
            {
                created = now;
                expires = now.Add(lifetime);
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
                    expires = now.Add(lifetime);
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
            => StringComparer.Ordinal.Equals(keyType, Constants.WsTrustKeyTypes.PublicKey) || StringComparer.Ordinal.Equals(keyType, MicrosoftKeyTypes.Asymmetric);

        protected virtual bool IsSupportedSymmetricKeyType(string keyType)
            => StringComparer.Ordinal.Equals(keyType, Constants.WsTrustKeyTypes.Symmetric) || StringComparer.Ordinal.Equals(keyType, MicrosoftKeyTypes.Symmetric);

        protected virtual bool IsSupportedBearerKeyType(string keyType)
            => StringComparer.Ordinal.Equals(keyType, Constants.WsTrustKeyTypes.Bearer) || StringComparer.Ordinal.Equals(keyType, MicrosoftKeyTypes.Bearer);

        protected virtual async ValueTask ApplyDefaultIssueValuesAsync(WsTrustRequest request, CancellationToken cancellationToken)
        {
            if (request.AppliesTo == null && Options.DefaultAppliesTo != null)
                request.AppliesTo = new AppliesTo(new EndpointReference(Options.DefaultAppliesTo));

            // TODO: try to do this only once
            var party = await GetRelyingPartyAsync(request.AppliesTo, cancellationToken);
            if (request.TokenType == null)
                request.TokenType = party?.DefaultTokenType ?? Options.DefaultTokenType;

            var keyType = string.IsNullOrEmpty(request.KeyType) ? Constants.WsTrustKeyTypes.Symmetric : request.KeyType;
            if (IsSupportedAsymmetricKeyType(keyType))
                request.KeyType = Constants.WsTrustKeyTypes.PublicKey;
            else if (IsSupportedSymmetricKeyType(keyType))
                request.KeyType = Constants.WsTrustKeyTypes.Symmetric;
            else if (IsSupportedBearerKeyType(keyType))
                request.KeyType = Constants.WsTrustKeyTypes.Bearer;
            else
                request.KeyType = keyType;

            if (request.KeyType == Constants.WsTrustKeyTypes.Symmetric && !request.KeySizeInBits.HasValue)
                request.KeySizeInBits = Options.DefaultSymmetricKeySizeInBits;
        }

        protected virtual ValueTask<RandomNumberGenerator> CreateRandomNumberGeneratorAsync() => new ValueTask<RandomNumberGenerator>(new RNGCryptoServiceProvider());

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
