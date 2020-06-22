using Microsoft.IdentityModel.Tokens;
using Solid.Identity.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{

    /// <summary>
    /// Defines one class which contains all the relying party related information.
    /// This class is not thread safe.
    /// </summary>
    public class Scope
    {
        /// <summary>
        /// Initializes an instance of <see cref="Scope"/>
        /// </summary>
        public Scope()
            : this(null, null, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="Scope"/>
        /// </summary>
        /// <param name="appliesToAddress">The appliesTo address of the relying party.</param>
        public Scope(string appliesToAddress)
            : this(appliesToAddress, null, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="Scope"/>
        /// </summary>
        /// <param name="appliesToAddress">The appliesTo address of the relying party.</param>
        /// <param name="signingKey">The signing credentials for the relying party.</param>
        public Scope(string appliesToAddress, SecurityKey signingKey)
            : this(appliesToAddress, signingKey, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="Scope"/>
        /// </summary>
        /// <param name="appliesToAddress">The appliesTo address of the relying party.</param>
        /// <param name="signingKey">The signing credentials for the relying party.</param>
        public Scope(string appliesToAddress, SecurityKey signingKey, SecurityAlgorithm signingAlgorithm)
            : this(appliesToAddress, signingKey, null, null, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="Scope"/>
        /// </summary>
        /// <param name="appliesToAddress">The appliesTo address of the relying party.</param>
        /// <param name="signingKey">The signing credentials for the relying party.</param>
        /// <param name="encryptingKey"> The encrypting credentials for the relying party.</param>
        public Scope(string appliesToAddress, SecurityKey signingKey, SecurityAlgorithm signingAlgorithm, SecurityKey encryptingKey, SecurityAlgorithm encryptingAlgorithm)
        {
            AppliesToAddress = appliesToAddress;
            SigningKey = signingKey;
            SigningAlgorithm = signingAlgorithm;
            EncryptingKey = encryptingKey;
            EncryptingAlgorithm = encryptingAlgorithm;
            Properties = new Dictionary<string, object>();
        }

        /// <summary>
        /// Gets or sets the appliesTo address of the relying party.
        /// </summary>
        public virtual string AppliesToAddress { get; set; }
        
        /// <summary>
        /// Gets or sets the replyTo address of the relying party.
        /// </summary>
        public virtual string ReplyToAddress { get; set; }

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
        public virtual SecurityAlgorithm EncryptingAlgorithm { get; private set; }

        /// <summary>
        /// Gets or sets the property which determines if issued symmetric keys must
        /// be encrypted by <see cref="Scope.EncryptingCredentials"/>.
        /// </summary>
        public virtual bool SymmetricKeyEncryptionRequired { get; set; }

        /// <summary>
        /// Gets or sets the property which determines if issued security tokens must
        /// be encrypted by <see cref="Scope.EncryptingCredentials"/>.
        /// </summary>
        public virtual bool TokenEncryptionRequired { get; set; }

        /// <summary>
        /// Gets the properties bag to extend the object.
        /// </summary>
        public virtual Dictionary<string, object> Properties { get; } 
    }
}
