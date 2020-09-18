using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Protocols.WsTrust.Abstractions;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    // TODO: add better xml documenation

    /// <summary>
    /// Defines one class which contains all the relying party related information.
    /// This class is not thread safe.
    /// </summary>
    public class Scope
    {
        public Scope(ClaimsIdentity subject, IRelyingParty party)
        {
            AppliesToAddress = party.AppliesTo;

            Subject = subject;
            RelyingParty = party;
        }

        public ClaimsIdentity Subject { get; }
        public IRelyingParty RelyingParty { get; }

        /// <summary>
        /// Gets or sets the appliesTo address of the relying party.
        /// </summary>
        public virtual string AppliesToAddress { get; set; }

        public virtual SigningCredentials SigningCredentials { get; set; }

        public virtual EncryptingCredentials EncryptingCredentials { get; set; }
    }
}
