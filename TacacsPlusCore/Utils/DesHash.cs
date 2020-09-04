using System;
using System.Linq;
using System.Security.Cryptography;

namespace Petrsnd.TacacsPlusCore.Utils
{
    public class DesHash
    {
        public static byte[] Convert7BitKey(byte[] inputKey)
        {
            var outputKey = new byte[8];
            outputKey[0] = (byte) (inputKey[0] >> 0x01);
            outputKey[1] = (byte) (((inputKey[0] & 0x01) << 6) | (inputKey[1] >> 2));
            outputKey[2] = (byte) (((inputKey[1] & 0x03) << 5) | (inputKey[2] >> 3));
            outputKey[3] = (byte) (((inputKey[2] & 0x07) << 4) | (inputKey[3] >> 4));
            outputKey[4] = (byte) (((inputKey[3] & 0x0F) << 3) | (inputKey[4] >> 5));
            outputKey[5] = (byte) (((inputKey[4] & 0x1F) << 2) | (inputKey[5] >> 6));
            outputKey[6] = (byte) (((inputKey[5] & 0x3F) << 1) | (inputKey[6] >> 7));
            outputKey[7] = (byte) (inputKey[6] & 0x7F);

            for (var i = 0; i < 8; i++)
            {
                outputKey[i] = (byte) ((outputKey[i] << 1) & 0xfe);
            }

            return outputKey;
        }

        public static byte[] ComputeHash(byte[] key, byte[] input)
        {
            var des = DES.Create();
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.KeySize = 64;

            if (key.Length % 7 != 0)
                throw new Exception("DES hash given key not evenly divisible by 7");

            if (input.Length % 8 != 0)
                throw new Exception("DES hash given input not evenly divisible by 8");

            if ((key.Length / 7) != (input.Length / 8))
                throw new Exception(
                    "DES hash not given equal number of blocks (7 and 8) of key and input respectively");

            var cipher = new byte[input.Length];
            for (var i = 0; i < (key.Length / 7); i += 1)
            {
                var plain = input.Skip(i * 8).Take(8).ToArray();
                des.Key = Convert7BitKey(key.Skip(i * 7).Take(7).ToArray());
                var enc = des.CreateEncryptor();
                var part = enc.TransformFinalBlock(plain, 0, 8);
                Buffer.BlockCopy(part, 0, cipher, i * 8, 8);
            }

            return cipher;
        }
    }
}
