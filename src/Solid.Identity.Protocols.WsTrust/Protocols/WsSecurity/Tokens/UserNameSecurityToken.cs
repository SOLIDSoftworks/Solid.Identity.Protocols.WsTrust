using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Tokens
{
    internal class UserNameSecurityToken : SecurityToken
    {
        public UserNameSecurityToken(string id, DateTime validFrom, DateTime validTo, string userName, string password, string passwordType)
        {
            Id = id;
            ValidFrom = validFrom;
            ValidTo = validTo;

            UserName = userName;
            Password = password;
            PasswordType = passwordType;
        }
        public string UserName { get; }
        public string Password { get; }
        public string PasswordType { get; }

        public override string Id { get; }
        public override string Issuer => null;
        public override SecurityKey SecurityKey => null;
        public override SecurityKey SigningKey { get => null; set { } }
        public override DateTime ValidFrom { get; }
        public override DateTime ValidTo { get; }
    }
}
