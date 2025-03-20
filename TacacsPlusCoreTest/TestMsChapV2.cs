using Petrsnd.TacacsPlusCore.Authentication;
using Petrsnd.TacacsPlusCore.Utils;
using System.ComponentModel.DataAnnotations;
using Xunit;

namespace Petrsnd.TacacsPlusCore.Test
{
    // Test data taken from RFC 2759 - 9.2
    public class TestMsChapV2
    {
        private readonly byte[] _authenticatorChallenge =
            {0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28};
        private readonly byte[] _peerChallenge =
            {0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E};


        [Fact]
        public void TestUser()
        {
            var expected = new byte[] {0x55, 0x73, 0x65, 0x72};
            var actual = "User".GetUserBuffer();
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestPassword()
        {
            var expected = new byte[]
            {
                0x63, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x50, 0x00, 0x61, 0x00,
                0x73, 0x00, 0x73, 0x00
            };
            var actual = MsChapV2.GetPasswordBuffer("clientPass".ToSecureString());
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestChallengeHash()
        {
            var expected = new byte[] {0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26};
            var actual =
                MsChapV2.GetChallengeHash(_authenticatorChallenge, _peerChallenge, "User".GetUserBuffer());
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestPasswordHash()
        {
            var expected = new byte[]
            {
                0x44, 0xEB, 0xBA, 0x8D, 0x53, 0x12, 0xB8, 0xD6, 0x11, 0x47, 0x44, 0x11, 0xF5, 0x69, 0x89, 0xAE
            };
            var actual = MsChapV2.GetNtPasswordHash("clientPass".ToSecureString());
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestNtResponse()
        {
            var expected = new byte[]
            {
                0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E, 0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
                0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF
            };
            var actual = MsChapV2.GetNtResponse(_authenticatorChallenge, _peerChallenge, "User".GetUserBuffer(),
                "clientPass".ToSecureString());
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestPasswordHashHash()
        {
            var expected = new byte[]
            {
                0x41, 0xC0, 0x0C, 0x58, 0x4B, 0xD2, 0xD9, 0x1C, 0x40, 0x17, 0xA2, 0xA1, 0x2F, 0xA5, 0x9F, 0x3F
            };
            var actual = MsChapV2.HashNtPasswordHash(MsChapV2.GetNtPasswordHash("clientPass".ToSecureString()));
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TestAuthenticatorResponse()
        {
            var expected = "S=407A5589115FD0D6209F510FE9C04566932CDA56";
            var ntResponse = MsChapV2.GetNtResponse(_authenticatorChallenge, _peerChallenge, "User".GetUserBuffer(),
                "clientPass".ToSecureString());
            var actual = MsChapV2.GenerateAuthenticatorResponse("clientPass".ToSecureString(), ntResponse,
                _peerChallenge, _authenticatorChallenge, "User".GetUserBuffer());
            Assert.Equal(expected, actual);
        }
    }
}
