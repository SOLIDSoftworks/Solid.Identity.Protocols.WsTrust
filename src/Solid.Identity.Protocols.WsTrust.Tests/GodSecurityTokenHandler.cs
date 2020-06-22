using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Solid.Identity.Protocols.WsTrust.Tests
{
    internal class GodSecurityTokenHandler : SecurityTokenHandler
    {
        public override Type TokenType => typeof(GodSecurityToken);

        public override string[] GetTokenTypeIdentifiers()
        {
            return new[]
            {
                "urn:god",
                "urn:deity"
            };
        }
        public override bool CanValidateToken => true;

        public override bool CanWriteToken => true;

        public override bool CanReadToken(XmlReader reader)
        {
            return reader.Name == "god:token" && reader.NamespaceURI == "urn:god";
        }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            var god = token as GodSecurityToken;
            if (god == null) throw new ArgumentException("Invalid god token");

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, god.Name),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Unspecified),
                new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddTHH:mm:ss.fffZ"), ClaimValueTypes.DateTime)
            };
            var identity = new ClaimsIdentity(claims, "omnipotence");

            if (Configuration.SaveBootstrapContext)
                identity.BootstrapContext = new BootstrapContext(god, this);

            return new List<ClaimsIdentity>
            {
                identity
            }.AsReadOnly();
        }

        public override SecurityToken ReadToken(XmlReader reader)
        {
            var content = reader.ReadElementContentAsString();
            return ReadToken(content);
        }

        public override SecurityToken ReadToken(string tokenString)
        {
            return new GodSecurityToken { Name = tokenString };
        }
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

    internal class GodSecurityToken : SecurityToken
    {
        public override string Id => Guid.NewGuid().ToString();

        public override ReadOnlyCollection<SecurityKey> SecurityKeys => new List<SecurityKey>().AsReadOnly();

        public override DateTime ValidFrom => DateTime.UtcNow;

        public override DateTime ValidTo => DateTime.UtcNow.AddHours(12);

        public string Name { get; set; }
    }
}
