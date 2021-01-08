using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace Solid.Identity.Protocols.WsTrust
{
    public class X509Name
    {
        public X509Name(string dn)
            : this(ParseDn(dn))
        {
            Dn = dn;
        }
        public X509Name(IDictionary<string, IEnumerable<string>> attributes)
        {
            Dn = Combine(attributes);
            Attributes = new ReadOnlyDictionary<string, IEnumerable<string>>(attributes);
        }

        public string Dn { get; }
        public IReadOnlyDictionary<string, IEnumerable<string>> Attributes { get; }

        public override bool Equals(object obj)
        {
            if (Object.Equals(obj, null)) return false;
            if (obj is X509Name name)
            {
                if (Dn == name.Dn) return true;
                // check: same amount of keys
                if (Attributes.Keys.Count() != name.Attributes.Keys.Count()) return false;
                // check: all key names match
                if (Attributes.Keys.Except(name.Attributes.Keys).Any()) return false;
                foreach (var pair in Attributes)
                {
                    if (pair.Value.Count() != name.Attributes[pair.Key].Count()) return false;
                    if (pair.Value.Except(name.Attributes[pair.Key]).Any()) return false;
                }
                return true;
            }
            return false;
        }

        public static bool TryParse(string dn, out X509Name name)
        {
            try
            {
                name = new X509Name(dn);
                return true;
            }
            catch (ArgumentException)
            {
                name = null;
                return false;
            }
        }

        public static X509Name Parse(string dn)
            => new X509Name(dn);

        public static bool operator ==(X509Name name1, X509Name name2)
        {
            if (Object.Equals(name1, null)) return Object.Equals(name2, null);
            return name1.Equals(name2) == true;
        }
        public static bool operator !=(X509Name name1, X509Name name2)
        {
            var equal = name1 == name2;
            return !equal;
        }

        static IDictionary<string, IEnumerable<string>> ParseDn(string dn)
        {
            var attributes = new Dictionary<string, List<string>>();
            var parts = dn.Split(',').Select(part => part.Trim());
            foreach (var part in parts)
            {
                var index = part.IndexOf('=');
                if (index == -1 || index + 1 == part.Length)
                    throw new ArgumentException("Not a valid distinguished name.", nameof(dn));
                var key = part.Substring(0, index);
                var value = part.Substring(index + 1);
                var list = null as List<string>;
                if (!attributes.TryGetValue(key, out list))
                {
                    list = new List<string>();
                    attributes.Add(key, list);
                }
                list.Add(value.Trim('"'));
            }
            return attributes.ToDictionary(p => p.Key, p => p.Value.AsEnumerable());
        }

        static string Combine(IDictionary<string, IEnumerable<string>> attributes)
            => string.Join(",", attributes.SelectMany(pair => pair.Value.Select(v => $"{pair.Key}={v}")));
    }
}
