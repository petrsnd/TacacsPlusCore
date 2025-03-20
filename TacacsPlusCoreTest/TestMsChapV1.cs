using System.Security;
using Petrsnd.TacacsPlusCore.Authentication;
using Petrsnd.TacacsPlusCore.Utils;
using Xunit;

namespace Petrsnd.TacacsPlusCore.Test
{
    public class TestMsChapV1
    {
        // test vectors from RFC 2433 -- B.2
        private readonly byte[] _challenge = {0x10, 0x2D, 0xB5, 0xDF, 0x08, 0x5D, 0x30, 0x41};
        private readonly SecureString _password = "MyPw".ToSecureString();

        [Fact]
        public void TestGetNtPasswordBuffer()
        {
            var expected = new byte[] {0x4D, 0x00, 0x79, 0x00, 0x50, 0x00, 0x77, 0x00};
            var actual = MsChapV1.GetNtPasswordBuffer(_password);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestGetNtPasswordHash()
        {
            var expected = new byte[]
                {0xFC, 0x15, 0x6A, 0xF7, 0xED, 0xCD, 0x6C, 0x0E, 0xDD, 0xE3, 0x33, 0x7D, 0x42, 0x7F, 0x4E, 0xAC};
            var actual = MsChapV1.GetNtPasswordHash(_password);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestGetNetChallengeResponse()
        {
            var expected = new byte[]
            {
                0x4E, 0x9D, 0x3C, 0x8F, 0x9C, 0xFD, 0x38, 0x5D, 0x5B, 0xF4, 0xD3, 0x24, 0x67, 0x91, 0x95, 0x6C, 0xA4,
                0xC3, 0x51, 0xAB, 0x40, 0x9A, 0x3D, 0x61
            };
            var actual = MsChapV1.GetNtChallengeResponse(_challenge, _password);
            Assert.Equal(expected, actual);
        }

        // unfortunately, there are no test vectors for the LAN MAN functions :(
        // but those are deprecated anyway in RFC 2433
    }
}
