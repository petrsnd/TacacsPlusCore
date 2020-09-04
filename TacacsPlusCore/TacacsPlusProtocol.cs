using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Petrsnd.TacacsPlusCore.Authentication;
using Petrsnd.TacacsPlusCore.Utils;

namespace Petrsnd.TacacsPlusCore
{
    public static class TacacsPlusProtocol
    {
        private static readonly RandomNumberGenerator Rng = new RNGCryptoServiceProvider();

        public static byte[] GetAuthenticationPacket(TacacsAuthenticationType type, TacacsAuthenticationService service,
            string user, SecureString password,
            SecureString sharedSecret)
        {
            byte[] intBuf = {0x00, 0x00, 0x00, 0x00};
            Rng.GetBytes(intBuf, 0, 4);
            var sessionId = BitConverter.ToInt32(intBuf, 0);

            var header = new TacacsHeader
            {
                Version = TacacsHeaderExtensions.VersionOne,
                Type = TacacsType.Authentication,
                SequenceNumber = 0x01,
                Flags = TacacsFlags.Encrypted,
                SessionId = sessionId,
                Length = 0
            };

            byte[] authenticationData;
            switch (type)
            {
                case TacacsAuthenticationType.Ascii:
                    throw new NotSupportedException("ASCII authentication method not supported");
                case TacacsAuthenticationType.Pap:
                    throw new NotSupportedException("PAP authentication method not supported");
                case TacacsAuthenticationType.Arap:
                    throw new NotSupportedException("ARAP authentication method not supported");
                case TacacsAuthenticationType.MsChap:
                    throw new NotSupportedException("MS-CHAP authentication method not supported");
                case TacacsAuthenticationType.Chap:
                    authenticationData = Chap.GetAuthenticationData(service, user, password);
                    break;
                case TacacsAuthenticationType.MsChapV2:
                    authenticationData = MsChapV2.GetAuthenticationData(service, user, password);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }

            return CreatePacket(header, authenticationData, sharedSecret);
        }

        public static byte[] CreatePacket(TacacsHeader header, byte[] data, SecureString sharedSecret)
        {
            header.Length = data.Length;
            var packetLength = 12 /* tacacs header len */ + data.Length;
            var packet = new byte[packetLength];
            var headerBuf = StructConverter.StructToBytes(header);
            Buffer.BlockCopy(headerBuf, 0, packet, 0, 12);
            var obfuscated = ObfuscateData(header, data, sharedSecret);
            Buffer.BlockCopy(obfuscated, 0, packet, 12, obfuscated.Length);
            return packet;
        }

        public static byte[] ObfuscateData(TacacsHeader header, byte[] data, SecureString sharedSecret)
        {
            var pseudoPad = GetPseudoPad(header, data.Length, sharedSecret);
            return XorPseudoPad(data, pseudoPad);
        }

        public static byte[] XorPseudoPad(byte[] data, byte[] pseudoPad)
        {
            var obfuscated = new byte[data.Length];
            for (var i = 0; i < pseudoPad.Length; i++)
                obfuscated[i] = (byte)(data[i] ^ pseudoPad[i]);
            return obfuscated;
        }

        public static byte[] GetPseudoPad(TacacsHeader header, int dataLength, SecureString sharedSecret)
        {
            var iterations = (dataLength / 16) + 1;
            var length = iterations * 16;
            var pseudoPad = new byte[length];

            using (var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5))
            {
                for (var i = 0; i < iterations; i++)
                {
                    var sessionIdBuf = BitConverter.GetBytes(header.SessionId);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(sessionIdBuf);
                    md5.AppendData(sessionIdBuf);

                    var sharedSecretPlain = sharedSecret.ToInsecureString();
                    var sharedSecretBytes = Encoding.UTF8.GetBytes(sharedSecretPlain);

                    md5.AppendData(sharedSecretBytes);
                    md5.AppendData(new[] {header.Version, header.SequenceNumber});
                    var preI = i - 1;
                    if (preI >= 0)
                        md5.AppendData(pseudoPad, preI * 16, 16);
                    var digest = md5.GetHashAndReset();
                    Buffer.BlockCopy(digest, 0, pseudoPad, i * 16, 16);
                }
            }

            return pseudoPad.Take(dataLength).ToArray();
        }
    }
}
