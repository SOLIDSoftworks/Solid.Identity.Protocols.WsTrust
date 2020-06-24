using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace Solid.ServiceModel.Security
{
    public class SecurityTokenHandlerCollection : IEnumerable<SecurityTokenHandler>
    {
        private IDictionary<string, SecurityTokenHandler> _handlersByTokenTypeIdentifier;
        private IDictionary<Type, SecurityTokenHandler> _handlersByTokenType;

        public SecurityTokenHandlerCollection()
            : this(new Dictionary<string, SecurityTokenHandler>(), new Dictionary<Type, SecurityTokenHandler>(), false)
        {

        }

        private SecurityTokenHandlerCollection(IDictionary<string, SecurityTokenHandler> handlersByTokenTypeIdentifier, IDictionary<Type, SecurityTokenHandler> handlersByTokenType, bool readOnly)
        {
            _handlersByTokenTypeIdentifier = new Dictionary<string, SecurityTokenHandler>();
            foreach (var pair in handlersByTokenTypeIdentifier)
                _handlersByTokenTypeIdentifier.Add(pair.Key, pair.Value);

            _handlersByTokenType = new Dictionary<Type, SecurityTokenHandler>();
            foreach (var pair in handlersByTokenType)
                _handlersByTokenType.Add(pair.Key, pair.Value);

            ReadOnly = readOnly;

            if(ReadOnly)
            {
                _handlersByTokenType = new ReadOnlyDictionary<Type, SecurityTokenHandler>(_handlersByTokenType);
                _handlersByTokenTypeIdentifier = new ReadOnlyDictionary<string, SecurityTokenHandler>(_handlersByTokenTypeIdentifier);
            }
        }

        public IEnumerable<string> TokenTypeIdentifiers => _handlersByTokenTypeIdentifier.Keys;
        public IEnumerable<Type> TokenTypes => _handlersByTokenType.Keys;

        public SecurityTokenHandler this[string tokenTypeIdentifier] => _handlersByTokenTypeIdentifier.TryGetValue(tokenTypeIdentifier, out var handler) ? handler : null;

        public SecurityTokenHandler this[SecurityToken token] => this[token?.GetType()];

        public SecurityTokenHandler this[Type tokenType] => _handlersByTokenType.TryGetValue(tokenType, out var handler) ? handler : null;

        public bool ReadOnly { get; }

        public void Add(SecurityTokenHandler handler, params string[] tokenTypeIdentifiers)
        {
            if (handler == null)
                throw new ArgumentNullException(nameof(handler));

            var type = handler.TokenType;
            if (_handlersByTokenType.ContainsKey(type))
                throw new ArgumentException("Handler already exists in collection.", nameof(handler));
            _handlersByTokenType.Add(type, handler);
            foreach(var identifier in tokenTypeIdentifiers)
            {
                if (_handlersByTokenTypeIdentifier.ContainsKey(identifier))
                    throw new ArgumentException($"Handler already registered with token type identifier '{identifier}'");
                _handlersByTokenTypeIdentifier.Add(identifier, handler);
            }
        }

        public SecurityTokenHandlerCollection Clone(bool readOnly = false) => new SecurityTokenHandlerCollection(_handlersByTokenTypeIdentifier, _handlersByTokenType, readOnly);

        public void Clear()
        {
            _handlersByTokenType.Clear();
            _handlersByTokenTypeIdentifier.Clear();
        }

        public virtual SecurityToken CreateToken(string tokenTypeIdentifier, SecurityTokenDescriptor tokenDescriptor)
        {
            if (!_handlersByTokenTypeIdentifier.TryGetValue(tokenTypeIdentifier, out var handler))
                throw new InvalidOperationException($"ID4020: Unable to create token with token identifier '{tokenTypeIdentifier}'");

            return handler.CreateToken(tokenDescriptor);
        }

        public virtual TSecurityToken CreateToken<TSecurityToken>(SecurityTokenDescriptor tokenDescriptor)
            where TSecurityToken : SecurityToken
        {
            var tokenType = typeof(TSecurityToken);
            if (!_handlersByTokenType.TryGetValue(tokenType, out var handler))
                throw new InvalidOperationException($"ID4020: Unable to create token of type '{tokenType.FullName}'");

            return handler.CreateToken(tokenDescriptor) as TSecurityToken;
        }

        public virtual bool CanReadToken(XmlReader reader) => this.Any(h => h.CanReadToken(reader));

        public virtual bool CanReadToken(string tokenString) => this.Any(h => h.CanReadToken(tokenString));

        public virtual bool CanWriteSecurityToken(SecurityToken securityToken) => this.Any(h => h.CanWriteSecurityToken(securityToken));

        public virtual SecurityToken ReadToken(string tokenString) => this.FirstOrDefault(h => h.CanReadToken(tokenString))?.ReadToken(tokenString);

        public virtual SecurityToken ReadToken(XmlReader reader) => this.FirstOrDefault(h => h.CanReadToken(reader))?.ReadToken(reader);

        public virtual SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters) => this.FirstOrDefault(h => h.CanReadToken(reader))?.ReadToken(reader, validationParameters);
        
        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            foreach(var handler in this)
            {
                if (!handler.CanReadToken(securityToken)) continue;
                if (!handler.CanValidateToken) continue;

                var principal = handler.ValidateToken(securityToken, validationParameters, out var token);
                if(principal != null)
                {
                    validatedToken = token;
                    return principal;
                }
            }

            validatedToken = null;
            return null;
        }

        public virtual ClaimsPrincipal ValidateToken(XmlReader reader, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            foreach (var handler in this)
            {
                if (!handler.CanReadToken(reader)) continue;
                if (!handler.CanValidateToken) continue;

                var principal = handler.ValidateToken(reader, validationParameters, out var token);
                if (principal != null)
                {
                    validatedToken = token;
                    return principal;
                }
            }

            validatedToken = null;
            return null;
        }

        public virtual string WriteToken(SecurityToken token)
        {
            var tokenType = token?.GetType();
            if (!_handlersByTokenType.TryGetValue(tokenType, out var handler))
                throw new InvalidOperationException($"ID4010: Unable to write token of type '{tokenType?.FullName}'");

            return handler.WriteToken(token);
        }

        public virtual void WriteToken(XmlWriter writer, SecurityToken token)
        {
            var tokenType = token?.GetType();
            if (!_handlersByTokenType.TryGetValue(tokenType, out var handler))
                throw new InvalidOperationException($"ID4010: Unable to write token of type '{tokenType?.FullName}'");

            handler.WriteToken(writer, token);
        }

        IEnumerator<SecurityTokenHandler> IEnumerable<SecurityTokenHandler>.GetEnumerator() => _handlersByTokenType.Values.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => _handlersByTokenType.Values.GetEnumerator();
    }
}
