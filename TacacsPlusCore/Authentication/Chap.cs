using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Petrsnd.TacacsPlusCore.Utils;

namespace Petrsnd.TacacsPlusCore.Authentication
{
    public static class Chap
    {
        private static readonly RandomNumberGenerator Rng = new RNGCryptoServiceProvider();
        private static readonly byte[] ClientPortName = Encoding.ASCII.GetBytes("chap");

        public static byte[] GetAuthenticationData(TacacsAuthenticationService service, string user,
            SecureString password)
        {
            var userBuf = user.GetUserBuffer();

            var authenticationHeader = new TacacsAuthenticationRequestHeader()
            {
                Action = TacacsAction.Login,
                PrivilegeLevel = 0x01,
                AuthenticationType = TacacsAuthenticationType.Chap,
                Service = service,
                UserLength = ((byte) userBuf.Length),
                PortLength = ((byte) ClientPortName.Length),
                RemoteLength = 0x00, // optional -- excluded
                DataLength = 0x42 // 66 bytes -- big challenge
            };

            var identifier = new byte[1];
            Rng.GetBytes(identifier, 0, 1);
            //var challenge = new byte[49];
            //Rng.GetBytes(challenge, 0, 32);
            var challenge = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789");

            var response = GetResponse(identifier, challenge, password);
            var data = new byte[1 /* identifier */ + 49 /* challenge */ + 16 /* response */];
            Buffer.BlockCopy(identifier, 0, data, 0, 1);
            Buffer.BlockCopy(challenge, 0, data, 1, 49);
            Buffer.BlockCopy(response, 0, data, 50, 16);

            var authenticationPacketLength =
                8 /* header */ + userBuf.Length + ClientPortName.Length + 0 /* remote */ + 66 /* CHAP length */;
            var authenticationPacket = new byte[authenticationPacketLength];
            var headerBuf = StructConverter.StructToBytes(authenticationHeader);
            Buffer.BlockCopy(headerBuf, 0, authenticationPacket, 0, 8);
            Buffer.BlockCopy(userBuf, 0, authenticationPacket, 8, userBuf.Length);
            Buffer.BlockCopy(ClientPortName, 0, authenticationPacket, 8 + userBuf.Length, ClientPortName.Length);
            Buffer.BlockCopy(data, 0, authenticationPacket, 8 + userBuf.Length + ClientPortName.Length, data.Length);

            return authenticationPacket;
        }

        public static byte[] GetResponse(byte[] identifier, byte[] challenge, SecureString password)
        {
            using (var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5))
            {
                md5.AppendData(identifier);
                var sharedSecretBytes = Encoding.UTF8.GetBytes(password.ToInsecureString());
                md5.AppendData(sharedSecretBytes);
                md5.AppendData(challenge);
                return md5.GetHashAndReset();
            }
        }
    }
}
