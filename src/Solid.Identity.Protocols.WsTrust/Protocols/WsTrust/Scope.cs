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
            SigningKey = party.SigningKey;
            SigningAlgorithm = party.SigningAlgorithm;
            EncryptingKey = party.EncryptingKey;
            EncryptingAlgorithm = party.EncryptingAlgorithm;

            Subject = subject;
            RelyingParty = party;
        }

        public ClaimsIdentity Subject { get; }
        public IRelyingParty RelyingParty { get; }

        /// <summary>
        /// Gets or sets the appliesTo address of the relying party.
        /// </summary>
        public virtual Uri AppliesToAddress { get; set; }
        
        ///// <summary>
        ///// Gets or sets the replyTo address of the relying party.
        ///// </summary>
        //public virtual string ReplyToAddress { get; set; }

        /// <summary>
        /// The signing <see cref="SecurityKey"/> for the relying party.
        /// </summary>
        public virtual SecurityKey SigningKey { get; set; }

        /// <summary>
        /// The signing <see cref="SecurityAlgorithm"/> for the relying party.
        /// </summary>
        public virtual SecurityAlgorithm SigningAlgorithm { get; set; }

        /// <summary>
        /// The encrypting <see cref="SecurityKey"/> for the relying party.
        /// </summary>
        public virtual SecurityKey EncryptingKey { get; set; }

        /// <summary>
        /// The encrypting <see cref="SecurityAlgorithm"/> for the relying party.
        /// </summary>
        public virtual SecurityAlgorithm EncryptingAlgorithm { get; set; }

        ///// <summary>
        ///// Gets or sets the property which determines if issued symmetric keys must
        ///// be encrypted by <see cref="EncryptingKey"/>.
        ///// </summary>
        //public virtual bool SymmetricKeyEncryptionRequired { get; set; }

        /// <summary>
        /// Gets or sets the property which determines if issued security tokens must
        /// be encrypted by <see cref="EncryptingKey"/>.
        /// </summary>
        public virtual bool TokenEncryptionRequired { get; set; }
    }
}
