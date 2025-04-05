using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Petrsnd.TacacsPlusCore.Utils;

namespace Petrsnd.TacacsPlusCore.Authentication
{
    public static class MsChapV1
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        private static readonly byte[] ClientPortName = Encoding.ASCII.GetBytes("net");

        public static byte[] GetAuthenticationData(TacacsAuthenticationService service, string user,
            SecureString password)
        {
            var userBuf = user.GetUserBuffer();

            var authenticationHeader = new TacacsAuthenticationRequestHeader()
            {
                Action = TacacsAction.Login,
                PrivilegeLevel = 0x01,
                AuthenticationType = TacacsAuthenticationType.MsChap,
                Service = service,
                UserLength = (byte)userBuf.Length,
                PortLength = (byte)ClientPortName.Length,
                RemoteLength = 0x00, // optional -- excluded
                DataLength = 0x3A // 58 bytes
            };

            // Challenge must be 8 bytes (see RFC 8907 5.4.2.4 and RFC 2433)
            var challenge = new byte[8];
            Rng.GetBytes(challenge, 0, 8);

            // RFC 2433 6 states that the LAN Manager compatible challenge has been deprecated
            // and should not be sent.  Instead this should be zero-filled.
            // var lmChallengeResponse = GetLmChallengeResponse(challenge, password);
            // Buffer.BlockCopy(Enumerable.Repeat((byte)0x00, 24).ToArray(), 0, lmChallengeResponse, 0, 24);
            var lmChallengeResponse = GetLmChallengeResponse();
            // RFC 2433 6, also see A.5
            var ntChallengeResponse = GetNtChallengeResponse(challenge, password);

            // MS-CHAPv1 response (49 bytes) -- see RFC 2433
            var challengeResponse = new byte[49];
            Buffer.BlockCopy(lmChallengeResponse, 0, challengeResponse, 0, 24);
            Buffer.BlockCopy(ntChallengeResponse, 0, challengeResponse, 24, 24);
            Buffer.BlockCopy(new byte[] { 0x01 }, 0, challengeResponse, 48, 1); // always set to 0x01 to use NT compatible challenge

            // ppp id
            var identifier = new byte[1];
            Rng.GetBytes(identifier, 0, 1);

            // RFC 8907 5.4.2.4 -- data = ppp id, challenge, response
            var data = new byte[58];  // ppp id (1 byte) + challenge (8 bytes) + response (49 bytes)
            Buffer.BlockCopy(identifier, 0, data, 0, 1);
            Buffer.BlockCopy(challenge, 0, data, 1, 8);
            Buffer.BlockCopy(challengeResponse, 0, data, 9, 49);

            // tacacs data
            var authenticationDataLength =
                8 /* header */ + userBuf.Length + ClientPortName.Length + 0 /* remote */ + 58 /* MsChap length */;
            var authenticationData = new byte[authenticationDataLength];
            var headerBuf = StructConverter.StructToBytes(authenticationHeader);
            Buffer.BlockCopy(headerBuf, 0, authenticationData, 0, 8);
            Buffer.BlockCopy(userBuf, 0, authenticationData, 8, userBuf.Length);
            Buffer.BlockCopy(ClientPortName, 0, authenticationData, 8 + userBuf.Length, ClientPortName.Length);
            Buffer.BlockCopy(data, 0, authenticationData, 8 + userBuf.Length + ClientPortName.Length, data.Length);

            return authenticationData;
        }
        
        public static byte[] GetLmChallengeResponse()
        {
            // Note that use of the LAN Manager compatible challenge response has been deprecated; peers SHOULD NOT generate it, and the sub-field SHOULD be zero-filled. See RFC 2433 6.Response Packet
            return Enumerable.Repeat((byte)0x00, 24).ToArray();
        }

        // public static byte[] GetLmChallengeResponse(byte[] challenge, SecureString password)
        // {
        //     var lmPasswordHash = GetLmPasswordHash(password);
        //     var key = new byte[21];
        //     Buffer.BlockCopy(lmPasswordHash, 0, key, 0, 16);
        //     Buffer.BlockCopy(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, key, 16, 5);
        //     var input = new byte[24];
        //     for (var i = 0; i < 3; i++)
        //         Buffer.BlockCopy(challenge, 0, input, i * 8, 8);
        //     return DesHash.ComputeHash(key, input);
        // }

        // public static byte[] GetLmPasswordHash(SecureString password)
        // {
        //     var passwordBuf = GetLmPasswordBuffer(password);
        //     var input = Encoding.ASCII.GetBytes("KGS!@#$%KGS!@#$%");
        //     return DesHash.ComputeHash(passwordBuf, input);
        // }

        // public static byte[] GetLmPasswordBuffer(SecureString password)
        // {
        //     var passwordArray = Encoding.ASCII.GetBytes(password.ToInsecureString().ToUpper()).ToList();
        //     for (var i = passwordArray.Count; i < 14; i++)
        //         passwordArray.Add(0x00);
        //     return passwordArray.Take(14).ToArray();
        // }

        public static byte[] GetNtChallengeResponse(byte[] challenge, SecureString password)
        {
            var ntPasswordHash = GetNtPasswordHash(password);
            var key = new byte[21];
            Buffer.BlockCopy(ntPasswordHash, 0, key, 0, 16);
            Buffer.BlockCopy(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, key, 16, 5);
            var input = new byte[24];
            for (var i = 0; i < 3; i++)
                Buffer.BlockCopy(challenge, 0, input, i * 8, 8);
            return DesHash.ComputeHash(key, input);
        }

        public static byte[] GetNtPasswordHash(SecureString password)
        {
            return Md4.ComputeHash(GetNtPasswordBuffer(password));
        }

        public static byte[] GetNtPasswordBuffer(SecureString password)
        {
            return Encoding.Unicode.GetBytes(password.ToInsecureString());
        }
    }
}
