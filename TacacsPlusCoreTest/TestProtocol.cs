using System.Linq;
using System.Text;
using Petrsnd.TacacsPlusCore.Utils;
using Xunit;

namespace Petrsnd.TacacsPlusCore.Test
{
    public class TestProtocol
    {
        [Fact]
        public void TestObfuscation()
        {
            var sharedSecret = "abcdefghijklmnopqrstuvwxyz123456".ToSecureString();
            var user = "booger";
            var password = "Test123".ToSecureString();

            var packet = TacacsPlusProtocol.GetAuthenticationPacket(TacacsAuthenticationType.MsChapV2,
                TacacsAuthenticationService.Login, user, password, sharedSecret);

            var header = StructConverter.BytesToStruct<TacacsHeader>(packet);
            Assert.Equal(0xc1, header.Version);
            Assert.Equal(TacacsFlags.Encrypted, header.Flags);
            Assert.Equal(0x53, header.Length);
            Assert.Equal(0x01, header.SequenceNumber);
            Assert.Equal(TacacsType.Authentication, header.Type);
            // Can't validate session number, because it is random

            var payload = packet.Skip(12).Take(packet.Length - 12).ToArray();
            var pseudoPad = TacacsPlusProtocol.GetPseudoPad(header, header.Length, sharedSecret);
            Assert.Equal(payload.Length, pseudoPad.Length);

            var plainPayload = TacacsPlusProtocol.XorPseudoPad(payload, pseudoPad);
            var authenticationHeader = StructConverter.BytesToStruct<TacacsAuthenticationRequestHeader>(plainPayload);

            // make sure we can read all the header values
            Assert.Equal(TacacsAuthenticationType.MsChapV2, authenticationHeader.AuthenticationType);
            Assert.Equal(TacacsAction.Login, authenticationHeader.Action);
            Assert.Equal(TacacsAuthenticationService.Login, authenticationHeader.Service);
            Assert.Equal(user.Length, authenticationHeader.UserLength);
            Assert.Equal("net".Length, authenticationHeader.PortLength);
            Assert.Equal(0x00, authenticationHeader.RemoteLength);
            Assert.Equal(0x42, authenticationHeader.DataLength);
        }
    }
}
