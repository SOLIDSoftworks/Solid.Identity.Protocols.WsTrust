using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust.Exceptions
{
    public class IdentityException : Exception
    {
        protected IdentityException(string code, params object[] args)
            : base(GetMessage(code, args)) => Code = code;

        private static string GetMessage(string code, object[] args) => ErrorMessages.GetFormattedMessage(code, args);

        public string Code { get; }
    }
}
