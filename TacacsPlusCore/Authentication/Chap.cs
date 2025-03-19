using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Petrsnd.TacacsPlusCore.Utils;

namespace Petrsnd.TacacsPlusCore.Authentication
{
    public static class Chap
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
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
                UserLength = (byte)userBuf.Length,
                PortLength = (byte)ClientPortName.Length,
                RemoteLength = 0x00, // optional -- excluded
                DataLength = 0x42 // 66 bytes -- identifier (1 byte) + big challenge (49 bytes) + response (16 bytes)
            };

            var identifier = new byte[1];
            Rng.GetBytes(identifier, 0, 1);
            var challenge = new byte[49];
            Rng.GetBytes(challenge, 0, 49);

            var response = GetResponse(identifier, challenge, password);
            var data = new byte[1 /* identifier */ + 49 /* challenge */ + 16 /* response */];
            Buffer.BlockCopy(identifier, 0, data, 0, 1);
            Buffer.BlockCopy(challenge, 0, data, 1, 49);
            Buffer.BlockCopy(response, 0, data, 50, 16);

            var authenticationDataLength =
                8 /* header */ + userBuf.Length + ClientPortName.Length + 0 /* remote */ + 66 /* CHAP data length */;
            var authenticationData = new byte[authenticationDataLength];
            var headerBuf = StructConverter.StructToBytes(authenticationHeader);
            Buffer.BlockCopy(headerBuf, 0, authenticationData, 0, 8);
            Buffer.BlockCopy(userBuf, 0, authenticationData, 8, userBuf.Length);
            Buffer.BlockCopy(ClientPortName, 0, authenticationData, 8 + userBuf.Length, ClientPortName.Length);
            Buffer.BlockCopy(data, 0, authenticationData, 8 + userBuf.Length + ClientPortName.Length, data.Length);

            return authenticationData;
        }

        public static byte[] GetResponse(byte[] identifier, byte[] challenge, SecureString password)
        {
            using (var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5))
            {
                md5.AppendData(identifier);
                var passwordBytes = Encoding.UTF8.GetBytes(password.ToInsecureString());
                md5.AppendData(passwordBytes);
                md5.AppendData(challenge);
                return md5.GetHashAndReset();
            }
        }
    }
}
