﻿using System.Linq;
using System.Text;
using Petrsnd.TacacsPlusCore.Authentication;
using Petrsnd.TacacsPlusCore.Utils;
using Xunit;

namespace Petrsnd.TacacsPlusCore.Test
{
    public class TestChap
    {
        // I couldn't find any test vectors for this, so I just used data generated by another open source tool

        [Fact]
        public void TestBufferFromTacTest()
        {
            // This packet was generated by tactest using the following command line:
            // .\tactest.exe -s 10.5.33.145 -k abcdefghijklmnopqrstuvwxyz123456 -u booger -p Test123 -type CHAP -challenge 1234567890123456789012345678901234567890123456789
            var packet = new byte[] {
                0xc1, 0x01, 0x01, 0x04, 0x6c, 0x94, 0xc2, 0xa8, 0x00, 0x00, 0x00, 0x50, 0x24, 0xa1, 0x35, 0x2a,
                0xf9, 0x9b, 0x78, 0xd9, 0xc1, 0xb1, 0xbe, 0xcd, 0x24, 0x95, 0xab, 0x48, 0x2f, 0xae, 0xdd, 0x1a,
                0x8a, 0xf0, 0x54, 0xa3, 0x28, 0x2b, 0x97, 0x12, 0x9e, 0x28, 0x58, 0x12, 0xff, 0x80, 0x7d, 0xff,
                0x7b, 0x73, 0xe5, 0xc6, 0xe7, 0xb7, 0xb1, 0x28, 0xb6, 0x1b, 0x94, 0xbb, 0x4f, 0x19, 0xeb, 0x4d,
                0xf7, 0x01, 0x0a, 0x1c, 0x06, 0x15, 0x06, 0xc8, 0x23, 0x15, 0xba, 0x23, 0xc7, 0xce, 0x4b, 0x38,
                0xf2, 0xa7, 0xa1, 0x70, 0x16, 0x9a, 0x30, 0xca, 0x17, 0x10, 0xb1, 0x5a
            };

            var user = "booger";
            var password = "Test123".ToSecureString();
            var sharedSecret = "abcdefghijklmnopqrstuvwxyz123456".ToSecureString();

            var header = StructConverter.BytesToStruct<TacacsHeader>(packet);
            Assert.Equal(0xc1, header.Version);
            Assert.Equal(TacacsFlags.SingleConnectionMode, header.Flags);
            Assert.Equal(0x50, header.Length);
            Assert.Equal(0x01, header.SequenceNumber);
            Assert.Equal(TacacsType.Authentication, header.Type);
            // Can't validate session number, because it is random

            var payload = packet.Skip(12).Take(packet.Length - 12).ToArray();
            var pseudoPad = TacacsPlusProtocol.GetPseudoPad(header, header.Length, sharedSecret);
            Assert.Equal(payload.Length, pseudoPad.Length);

            var plainPayload = TacacsPlusProtocol.XorPseudoPad(payload, pseudoPad);
            var authenticationHeader = StructConverter.BytesToStruct<TacacsAuthenticationRequestHeader>(plainPayload);

            Assert.Equal(TacacsAuthenticationType.Chap, authenticationHeader.AuthenticationType);
            Assert.Equal(TacacsAction.Login, authenticationHeader.Action);
            Assert.Equal(TacacsAuthenticationService.None, authenticationHeader.Service);
            Assert.Equal(user.Length, authenticationHeader.UserLength);
            Assert.Equal(0x00, authenticationHeader.PortLength);
            Assert.Equal(0x00, authenticationHeader.RemoteLength);
            Assert.Equal(0x42, authenticationHeader.DataLength);

            var authenticationData = plainPayload.Skip(plainPayload.Length - 0x42).Take(0x42).ToArray();
            var identifier = authenticationData.Take(1).ToArray();
            var hardcodedChallenge = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789");
            var challenge = authenticationData.Skip(1).Take(hardcodedChallenge.Length).ToArray();
            Assert.Equal(hardcodedChallenge, challenge);

            // Verify that we can generate the same response
            var calculated = Chap.GetResponse(identifier, challenge, password);
            var expected = authenticationData.Skip(1 + challenge.Length).ToArray();
            Assert.Equal(expected, calculated);
        }
    }
}
