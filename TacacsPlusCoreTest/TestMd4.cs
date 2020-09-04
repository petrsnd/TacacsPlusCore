using System.Text;
using Petrsnd.TacacsPlusCore.Utils;
using Xunit;

namespace Petrsnd.TacacsPlusCore.Test
{
    public class TestMd4
    {
        [Fact]
        public void TestByteArrays()
        {
            Assert.Equal(new byte[] { 0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0 },
                Md4.ComputeHash(new byte[0]));

            Assert.Equal(new byte[] { 0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b }, 
                Md4.ComputeHash(Encoding.ASCII.GetBytes("message digest")));

            Assert.Equal(new byte[] { 0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35, 0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7, 0xf0, 0xe4 },
                Md4.ComputeHash(Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")));
        }

        [Fact]
        public void TestStrings()
        {
            Assert.Equal("31d6cfe0d16ae931b73c59d7e0c089c0", "".Md4Hash());
            Assert.Equal("bde52cb31de33e46245e05fbdbd6fb24", "a".Md4Hash());
            Assert.Equal("a448017aaf21d8525fc10ae87aa6729d", "abc".Md4Hash());
            Assert.Equal("d9130a8164549fe818874806e1c7014b", "message digest".Md4Hash());
            Assert.Equal("d79e1c308aa5bbcdeea8ed63df412da9", "abcdefghijklmnopqrstuvwxyz".Md4Hash());
            Assert.Equal("043f8582f241db351ce627e153e7f0e4",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".Md4Hash());
            Assert.Equal("e33b4ddc9c38f2199c3e7b164fcc0536",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890".Md4Hash());
        }
    }
}
