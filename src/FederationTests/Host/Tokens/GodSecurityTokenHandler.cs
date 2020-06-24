using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Protocols.WsTrust.Tests.Host.Tokens
{
    public class GodSecurityTokenHandler : SecurityTokenHandler
    {
        public override Type TokenType => typeof(GodSecurityToken);

        public string[] GetTokenTypeIdentifiers()
        {
            return new[]
            {
                "urn:god",
                "urn:deity"
            };
        }

        public override bool CanValidateToken => true;

        public override bool CanWriteToken => true;

        public override ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters _, out SecurityToken validatedToken)
        {
            validatedToken = ReadToken(securityToken);
            var identities = ValidateToken(validatedToken);
            return new ClaimsPrincipal(identities);
        }

        public override ClaimsPrincipal ValidateToken(XmlReader reader, TokenValidationParameters _, out SecurityToken validatedToken)
        {
            validatedToken = ReadToken(reader);
            var identities = ValidateToken(validatedToken);
            return new ClaimsPrincipal(identities);
        }

        public IReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            var god = token as GodSecurityToken;
            if (god == null) throw new ArgumentException("Invalid god token");

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, god.Name),
                new Claim(ClaimTypes.AuthenticationMethod, "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/unspecified"),
                new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddTHH:mm:ss.fffZ"), ClaimValueTypes.DateTime)
            };
            var identity = new ClaimsIdentity(claims, "omnipotence");

            return new List<ClaimsIdentity>
            {
                identity
            }.AsReadOnly();
        }

        public override bool CanReadToken(XmlReader reader)
            => reader.Name == "god:token" && GetTokenTypeIdentifiers().Contains(reader.NamespaceURI);

        public override bool CanReadToken(string tokenString)
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(tokenString)))
            using (var reader = XmlReader.Create(stream))
            {
                reader.MoveToContent();
                return CanReadToken(reader);
            }
        }

        public override bool CanWriteSecurityToken(SecurityToken securityToken) => securityToken is GodSecurityToken;

        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters _) => ReadToken(reader);
        
        public override SecurityToken ReadToken(XmlReader reader)
        {
            var content = reader.ReadElementContentAsString();
            return ReadToken(content);
        }

        public override SecurityToken ReadToken(string tokenString)
            => new GodSecurityToken { Name = tokenString };

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            var name = tokenDescriptor.Subject.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            return new GodSecurityToken { Name = name };
        }

        public override string WriteToken(SecurityToken token)
        {
            var god = token as GodSecurityToken;
            if (god == null) throw new ArgumentException("Invalid god token");

            return god.Name;
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            var god = token as GodSecurityToken;
            if (god == null) throw new ArgumentException("Invalid god token");

            writer.WriteStartElement("god", "token", "urn:god");
            writer.WriteAttributeString("ValueType", "urn:god");
            writer.WriteValue(WriteToken(token));
            writer.WriteEndElement();
        }
    }

    public class GodSecurityToken : SecurityToken
    {
        public override string Id => Guid.NewGuid().ToString();

        public override string Issuer => "urn:alpha:and:omega";

        public override SecurityKey SecurityKey => null;

        public override SecurityKey SigningKey { get => null; set { } }

        public override DateTime ValidFrom => DateTime.MinValue;

        public override DateTime ValidTo => DateTime.MaxValue;

        public string Name { get; set; }
    }
}
