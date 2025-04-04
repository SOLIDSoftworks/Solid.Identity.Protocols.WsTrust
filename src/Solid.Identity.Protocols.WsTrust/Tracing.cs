using System.Diagnostics;

namespace Solid.Identity
{
    public static class Tracing
    {
        public static class WsSecurity
        {
            public static ActivitySource Base { get; } = new (Names.WsSecurity.Base, GenerateAssemblyVersion());
            public static ActivitySource Tokens { get; } = new (Names.WsSecurity.Tokens, GenerateAssemblyVersion());
            public static ActivitySource Xml { get; } = new (Names.WsSecurity.Xml, GenerateAssemblyVersion());
        }
        
        public static class Names
        {
            public static class WsTrust
            {
                public const string Base = "Solid.Identity.Protocols.WsTrust";
            }

            public static class WsSecurity
            {
                public static string[] All => new[]
                {
                    Base,
                    Tokens,
                    Xml
                };
                
                public const string Base = "Solid.Identity.Protocols.WsSecurity";
                public const string Tokens = Base + ".Tokens";
                public const string Xml = Base + ".Xml";
            }
        }

        private static string GenerateAssemblyVersion()
        {
            var version = typeof(Tracing).Assembly.GetName().Version;
            return version == null ? "0.0.0" : $"{version.Major}.{version.Minor}.{version.Build}";
        }
    }
}