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
                AuthenticationType = TacacsAuthenticationType.MsChapV2,
                Service = service,
                UserLength = (byte)userBuf.Length,
                PortLength = (byte)ClientPortName.Length,
                RemoteLength = 0x00, // optional -- excluded
                DataLength = 0x42 // 66 bytes
            };

            // see RFC 2759 4 for definition of the challenge response data:
            //    peer challenge (16 bytes)
            //    reserved zeros (8 bytes)
            //    NT response (24 bytes)
            //    Flag -- always zero (1 byte)
            var challengeResponse = new byte[49];
            // [data] peer challenge -- 16 bytes (random)
            var peerChallenge = new byte[16];
            Rng.GetBytes(peerChallenge, 0, 16);
            Buffer.BlockCopy(peerChallenge, 0, challengeResponse, 0, 16);
            // [data] reserved -- 8 bytes (zeroes)
            for (var i = 16; i < 24; i++)
                Buffer.SetByte(challengeResponse, i, 0x00);
            // generate random "received" challenge (this would be from the authenticator in RFC 2759)
            var authenticatorChallenge = new byte[16];
            Rng.GetBytes(authenticatorChallenge, 0, 16);
            // [data] NT-response -- 24 bytes calculated from password, username, peer challenge, and "received" (from authenticator) challenge
            var ntResponse = GetNtResponse(authenticatorChallenge, peerChallenge, userBuf, password);
            Buffer.BlockCopy(ntResponse, 0, challengeResponse, 24, 24);
            // flag -- 1 byte (zero)
            Buffer.SetByte(challengeResponse, 48, 0x00);

            var identifier = new byte[1];
            Rng.GetBytes(identifier, 0, 1);

            // RFC 8907 5.4.2.5 -- data = ppp id, challenge, challenge response
            var data = new byte[66];
            Buffer.BlockCopy(identifier, 0, data, 0, 1);
            Buffer.BlockCopy(authenticatorChallenge, 0, data, 1, 16);
            Buffer.BlockCopy(challengeResponse, 0, data, 17, 49); // The peerChallenge is already included in the challengeResponse above

            // tacacs data
            var authenticationDataLength =
                8 /* header */ + userBuf.Length + ClientPortName.Length + 0 /* remote */ + data.Length /* MsChapV2 length */;
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
            ValidateChallenges(authenticatorChallenge, peerChallenge);

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
            ValidateChallenges(authenticatorChallenge, peerChallenge);

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

        public static byte[] HashNtPasswordHash(byte[] passwordHash)
        {
            return Md4.ComputeHash(passwordHash);
        }

        public static string GenerateAuthenticatorResponse(SecureString password, byte[] ntResponse,
            byte[] peerChallenge, byte[] authenticatorChallenge, byte[] userBuf)
        {
            ValidateChallenges(authenticatorChallenge, peerChallenge);

            var magic1 = new byte[]
            {
                0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
                0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
                0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
                0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74
            };

            var magic2 = new byte[]
            {
                0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
                0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
                0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
                0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
                0x6E
            };

            var passwordHash = GetNtPasswordHash(password);
            var passwordHashHash = HashNtPasswordHash(passwordHash);

            byte[] digest1;
            using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                sha.AppendData(passwordHashHash);
                sha.AppendData(ntResponse);
                sha.AppendData(magic1);
                digest1 = sha.GetHashAndReset();
            }

            var challengeHash = GetChallengeHash(authenticatorChallenge, peerChallenge, userBuf);

            byte[] digest2;
            using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                sha.AppendData(digest1);
                sha.AppendData(challengeHash);
                sha.AppendData(magic2);
                digest2 = sha.GetHashAndReset();
            }

            return $"S={BitConverter.ToString(digest2).Replace("-", string.Empty)}";
        }

        public static byte[] GetPasswordBuffer(SecureString password)
        {
            return Encoding.Unicode.GetBytes(password.ToInsecureString());
        }

        private static void ValidateChallenges(byte[] authenticatorChallenge, byte[] peerChallenge)
        {
            if (authenticatorChallenge.Length != 16)
            {
                throw new ArgumentException("Authenticator challenge must be 16 bytes");
            }

            if (peerChallenge.Length != 16)
            {
                throw new ArgumentException("Peer challenge must be 16 bytes");
            }
        }
    }
}
