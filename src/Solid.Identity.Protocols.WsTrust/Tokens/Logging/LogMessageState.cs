using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Solid.Identity.Tokens.Logging
{
    internal class LogMessageState
    {
        public override string ToString() => JsonSerializer.Serialize(this, GetType(), new JsonSerializerOptions { WriteIndented = true });
    }
}
