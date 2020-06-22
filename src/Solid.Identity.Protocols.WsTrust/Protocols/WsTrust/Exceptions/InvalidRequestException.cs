using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Exceptions
{
    public class InvalidRequestException : IdentityException
    {
        public InvalidRequestException(string code, params object[] args) 
            : base(code, args)
        {
        }
    }
}
