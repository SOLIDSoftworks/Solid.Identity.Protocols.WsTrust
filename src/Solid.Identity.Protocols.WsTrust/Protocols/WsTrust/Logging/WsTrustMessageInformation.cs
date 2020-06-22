using Microsoft.IdentityModel.Protocols.WsTrust;
using Solid.Identity.Tokens.Logging;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;
using System.Text.Json.Serialization;

namespace Solid.Identity.Protocols.WsTrust.Logging
{
    internal class WsTrustMessageInformation : LogMessageState
    {
        public string RequestAction { get; set; }

        public string ResponseAction { get; set; }

        public string TrustNamespace { get; set; }

        [JsonIgnore]
        public WsTrustVersion WsTrustVersion { get; set; }

        public string Version => GetWsTrustVersionString(WsTrustVersion);

        private string GetWsTrustVersionString(WsTrustVersion version)
        {
            if (version == WsTrustVersion.Trust13) return nameof(WsTrustVersion.Trust13);
            if (version == WsTrustVersion.Trust14) return nameof(WsTrustVersion.Trust14);
            if (version == WsTrustVersion.TrustFeb2005) return nameof(WsTrustVersion.TrustFeb2005);

            return "unknown";
        }
    }
}
