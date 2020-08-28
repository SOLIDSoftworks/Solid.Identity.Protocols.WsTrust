using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Exceptions
{
    public class UnsupportedTokenTypeBadRequestException : Exception
    {
        public UnsupportedTokenTypeBadRequestException(string tokenType)
            : base($"An unsupported token type was requested: {tokenType}")
        {
        }
    }
}
