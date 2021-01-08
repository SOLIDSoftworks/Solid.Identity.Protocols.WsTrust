using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Solid.Identity.Protocols.WsTrust.Tests
{
    public class X509NameTests
    {
        [Theory]
        [InlineData("CN=person1, OU=dept1, O=org1", "O=org1, OU=dept1, CN=person1")]
        [InlineData(null, null)]
        public void ShouldBeEqual(string dn1, string dn2)
        {
            var name1 = dn1 != null ? new X509Name(dn1) : null;
            var name2 = dn2 != null ? new X509Name(dn2) : null;

            Assert.Equal(name1, name2);
            if(name1 != null)
                Assert.True(name1.Equals(name2));
            Assert.True(name1 == name2);
            Assert.False(name1 != name2);
        }

        [Theory]
        [InlineData("CN=person1, OU=dept1, O=org1", "CN=person2, OU=dept2, O=org1")]
        [InlineData("O=org1, OU=dept1, CN=person1", "CN=person2, OU=dept2, O=org1")]
        [InlineData("O=org1, OU=dept1, CN=person1", null)]
        public void ShouldNotBeEqual(string dn1, string dn2)
        {
            var name1 = dn1 != null ? new X509Name(dn1) : null;
            var name2 = dn2 != null ? new X509Name(dn2) : null;

            Assert.NotEqual(name1, name2);
            if (name1 != null)
                Assert.False(name1.Equals(name2));
            if (name2 != null)
                Assert.False(name2.Equals(name1));
            Assert.False(name1 == name2);
            Assert.True(name1 != name2);
        }

        [Fact]
        public void ShouldParseStringDn()
        {
            var dn = "CN=person1, OU=dept1, O=org1";
            var name = new X509Name(dn);

            Assert.NotEmpty(name.Attributes);

            Assert.Contains("CN", name.Attributes);
            Assert.Equal("person1", name.Attributes["CN"].Single());
            Assert.Contains("OU", name.Attributes);
            Assert.Equal("dept1", name.Attributes["OU"].Single());
            Assert.Contains("O", name.Attributes);
            Assert.Equal("org1", name.Attributes["O"].Single());
        }

        [Theory]
        [InlineData("CN=person1, OU=dept1 O=org1")]
        [InlineData("CN=person1, OU=\"dept1 O=org1\"")]
        public void ShouldParseInvalidStringDn(string dn)
        {
            var name = new X509Name(dn);

            Assert.NotEmpty(name.Attributes);

            Assert.Contains("CN", name.Attributes);
            Assert.Equal("person1", name.Attributes["CN"].Single());
            Assert.Contains("OU", name.Attributes);
            Assert.Equal("dept1 O=org1", name.Attributes["OU"].Single());
            Assert.DoesNotContain("O", name.Attributes);
        }

        [Theory]
        [InlineData("CN=person1, OU=dept1, O=org1", true)]
        public void ShouldTryParseStringDn(string dn, bool success)
        {
            Assert.Equal(success, X509Name.TryParse(dn, out var name));
            if (!success)
            {
                Assert.Null(name);
                return;
            }

            Assert.NotEmpty(name.Attributes);

            Assert.Contains("CN", name.Attributes);
            Assert.Equal("person1", name.Attributes["CN"].Single());
            Assert.Contains("OU", name.Attributes);
            Assert.Equal("dept1", name.Attributes["OU"].Single());
            Assert.Contains("O", name.Attributes);
            Assert.Equal("org1", name.Attributes["O"].Single());
        }

        [Fact]
        public void ShouldHandleDuplicateKeys()
        {
            var dn = "CN=person1, DC=domain, DC=com";
            var name = new X509Name(dn);

            Assert.NotEmpty(name.Attributes);

            Assert.Contains("CN", name.Attributes);
            Assert.Equal("person1", name.Attributes["CN"].Single());
            Assert.Contains("DC", name.Attributes);
            Assert.Contains("domain", name.Attributes["DC"]);
            Assert.Contains("com", name.Attributes["DC"]);
        }
    }
}
