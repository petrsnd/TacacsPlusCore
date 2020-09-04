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

        public static byte[] GetPasswordBuffer(SecureString password)
        {
            return Encoding.Unicode.GetBytes(password.ToInsecureString());
        }

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

            var challengeResponse = new byte[49];
            // challenge -- 16 bytes
            Buffer.BlockCopy(authenticatorChallenge, 0, challengeResponse, 0, 16);
            // reserved -- 8 bytes (zeroes)
            for (var i = 16; i < 24; i++)
                Buffer.SetByte(challengeResponse, i, 0x00);
            // NT-response -- 24 bytes
            var ntResponse = GetNtResponse(authenticatorChallenge, peerChallenge, userBuf, password);
            Buffer.BlockCopy(ntResponse, 0, challengeResponse, 24, 24);
            // flags -- 1 byte (zero)
            Buffer.SetByte(challengeResponse, 48, 0);

            var data = new byte[66];
            Buffer.SetByte(data, 0, 0x0f); // PPP id (always 15?)
            Buffer.BlockCopy(peerChallenge, 0, data, 1, 16);
            Buffer.BlockCopy(challengeResponse, 0, data, 17, 49);

            var authenticationPacketLength =
                8 /* header */ + userBuf.Length + ClientPortName.Length + 0 /* remote */ + 66 /* MsChapV2 length */;
            var authenticationPacket = new byte[authenticationPacketLength];
            var headerBuf = StructConverter.StructToBytes(authenticationHeader);
            Buffer.BlockCopy(headerBuf, 0, authenticationPacket, 0, 8);
            Buffer.BlockCopy(userBuf, 0, authenticationPacket, 8, userBuf.Length);
            Buffer.BlockCopy(ClientPortName, 0, authenticationPacket, 8 + userBuf.Length, ClientPortName.Length);
            Buffer.BlockCopy(data, 0, authenticationPacket, 8 + userBuf.Length + ClientPortName.Length, data.Length);

            return authenticationPacket;
        }

        public static byte[] GetNtResponse(byte[] authenticatorChallenge, byte[] peerChallenge, byte[] userBuf,
            SecureString password)
        {
            var challengeHash = GetChallengeHash(authenticatorChallenge, peerChallenge, userBuf);
            var passwordHash = GetNtPasswordHash(password);
            var des = DES.Create();
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.KeySize = 64;
            des.Key = Convert7BitKey(passwordHash.Take(7).ToArray());
            var ct = des.CreateEncryptor();
            var pt1 = ct.TransformFinalBlock(challengeHash, 0, 8);

            des.Key = Convert7BitKey(passwordHash.Skip(7).Take(7).ToArray());
            ct = des.CreateEncryptor();
            var pt2 = ct.TransformFinalBlock(challengeHash, 0, 8);

            var finalKey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            Buffer.BlockCopy(passwordHash, 14, finalKey, 0, 2);
            des.Key = Convert7BitKey(finalKey);
            ct = des.CreateEncryptor();
            var pt3 = ct.TransformFinalBlock(challengeHash, 0, 8);

            var response = new byte[24];
            Buffer.BlockCopy(pt1, 0, response, 0, 8);
            Buffer.BlockCopy(pt2, 0, response, 8, 8);
            Buffer.BlockCopy(pt3, 0, response, 16, 8);
            return response;
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

        private static byte[] Convert7BitKey(byte[] inputKey)
        {
            var outputKey = new byte[8];
            outputKey[0] = (byte)(inputKey[0] >> 0x01);
            outputKey[1] = (byte)(((inputKey[0] & 0x01) << 6) | (inputKey[1] >> 2));
            outputKey[2] = (byte)(((inputKey[1] & 0x03) << 5) | (inputKey[2] >> 3));
            outputKey[3] = (byte)(((inputKey[2] & 0x07) << 4) | (inputKey[3] >> 4));
            outputKey[4] = (byte)(((inputKey[3] & 0x0F) << 3) | (inputKey[4] >> 5));
            outputKey[5] = (byte)(((inputKey[4] & 0x1F) << 2) | (inputKey[5] >> 6));
            outputKey[6] = (byte)(((inputKey[5] & 0x3F) << 1) | (inputKey[6] >> 7));
            outputKey[7] = (byte)(inputKey[6] & 0x7F);

            for (var i = 0; i < 8; i++)
            {
                outputKey[i] = (byte)((outputKey[i] << 1) & 0xfe);
            }

            return outputKey;
        }
    }
}
