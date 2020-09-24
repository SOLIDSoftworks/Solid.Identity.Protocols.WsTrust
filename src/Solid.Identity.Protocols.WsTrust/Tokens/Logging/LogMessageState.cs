using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Solid.Identity.Tokens.Logging
{
    /// <summary>
    /// A base class used for log state
    /// </summary>
    public abstract class LogMessageState
    {
        /// <summary>
        /// JSON serializes the class with indents
        /// </summary>
        /// <returns>An indented JSON representation of the current class.</returns>
        public override string ToString() => JsonSerializer.Serialize(this, GetType(), new JsonSerializerOptions { WriteIndented = true });
    }
}
