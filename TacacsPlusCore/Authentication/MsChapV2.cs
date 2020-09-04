using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Petrsnd.TacacsPlusCore.Utils;

namespace Petrsnd.TacacsPlusCore.Authentication
{
    public static class MsChapV2
    {
        private static readonly RandomNumberGenerator Rng = new RNGCryptoServiceProvider();
        private static readonly byte[] ClientPortName = Encoding.ASCII.GetBytes("net");

        public static byte[] GetAuthenticationData(TacacsAuthenticationService service, string user,
            SecureString password)
        {
            var userBuf = user.GetUserBuffer();

            var authenticationHeader = new TacacsAuthenticationRequestHeader()
            {
                Action = TacacsAction.Login,
                PrivilegeLevel = 0x01,
                AuthenticationType = TacacsAuthenticationType.MsChapV2,
                Service = service,
                UserLength = ((byte) userBuf.Length),
                PortLength = ((byte) ClientPortName.Length),
                RemoteLength = 0x00, // optional -- excluded
                DataLength = 0x42 // 66 bytes
            };

            var authenticatorChallenge = new byte[16];
            var peerChallenge = new byte[16];
            Rng.GetBytes(authenticatorChallenge, 0, 16);
            Rng.GetBytes(peerChallenge, 0, 16);

            // see RFC 2433
            var challengeResponse = new byte[49];
            // challenge -- 16 bytes
            Buffer.BlockCopy(peerChallenge, 0, challengeResponse, 0, 16);
            // reserved -- 8 bytes (zeroes)
            for (var i = 16; i < 24; i++)
                Buffer.SetByte(challengeResponse, i, 0x00);
            // NT-response -- 24 bytes
            var ntResponse = GetNtResponse(authenticatorChallenge, peerChallenge, userBuf, password);
            Buffer.BlockCopy(ntResponse, 0, challengeResponse, 24, 24);
            // flags -- 1 byte (zero)
            Buffer.SetByte(challengeResponse, 48, 0);

            var identifier = new byte[1];
            Rng.GetBytes(identifier, 0, 1);

            // draft 18 -- 5.4.2.5
            var data = new byte[66];
            Buffer.BlockCopy(identifier, 0, data, 0, 1);
            Buffer.BlockCopy(authenticatorChallenge, 0, data, 1, 16);
            Buffer.BlockCopy(challengeResponse, 0, data, 17, 49);

            // tacacs data
            var authenticationDataLength =
                8 /* header */ + userBuf.Length + ClientPortName.Length + 0 /* remote */ + 66 /* MsChapV2 length */;
            var authenticationData = new byte[authenticationDataLength];
            var headerBuf = StructConverter.StructToBytes(authenticationHeader);
            Buffer.BlockCopy(headerBuf, 0, authenticationData, 0, 8);
            Buffer.BlockCopy(userBuf, 0, authenticationData, 8, userBuf.Length);
            Buffer.BlockCopy(ClientPortName, 0, authenticationData, 8 + userBuf.Length, ClientPortName.Length);
            Buffer.BlockCopy(data, 0, authenticationData, 8 + userBuf.Length + ClientPortName.Length, data.Length);

            return authenticationData;
        }

        public static byte[] GetNtResponse(byte[] authenticatorChallenge, byte[] peerChallenge, byte[] userBuf,
            SecureString password)
        {
            var challengeHash = GetChallengeHash(authenticatorChallenge, peerChallenge, userBuf);
            var input = new byte[24];
            for (var i = 0; i < 3; i++)
                Buffer.BlockCopy(challengeHash, 0, input, i * 8, 8);
            var passwordHash = GetNtPasswordHash(password);
            var key = new byte[21];
            Buffer.BlockCopy(passwordHash, 0, key, 0, 16);
            Buffer.BlockCopy(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, key, 16, 5);
            return DesHash.ComputeHash(key, input);
        }

        public static byte[] GetChallengeHash(byte[] authenticatorChallenge, byte[] peerChallenge, byte[] userBuf)
        {
            using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                sha.AppendData(peerChallenge);
                sha.AppendData(authenticatorChallenge);
                sha.AppendData(userBuf);
                return sha.GetHashAndReset().Take(8).ToArray();
            }
        }

        public static byte[] GetNtPasswordHash(SecureString password)
        {
            return Md4.ComputeHash(GetPasswordBuffer(password));
        }

        public static byte[] GetPasswordBuffer(SecureString password)
        {
            return Encoding.Unicode.GetBytes(password.ToInsecureString());
        }
    }
}
