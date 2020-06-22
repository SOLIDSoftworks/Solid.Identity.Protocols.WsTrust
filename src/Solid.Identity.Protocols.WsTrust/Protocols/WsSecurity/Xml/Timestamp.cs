using System;
using System.Collections.Generic;
using System.Text;

namespace Solid.Identity.Protocols.WsSecurity.Xml
{
    [Serializable]
    internal class Timestamp
    {
        public string Id { get; set; }
        public DateTime Created { get; set; }
        public DateTime Expires { get; set; }
    }
}
