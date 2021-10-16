using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace MayMeow.Cryptography
{
    public class GCM
    {

        public byte[] _key;
        public byte[] _nonce;

        public static int KEY_BYTES = 16;
        public static int NONCE_BYTES = 12;

        /// <summary>
        /// Using AesGcm to entcryption
        /// </summary>
        /// <param name="key"></param>
        /// <param name="nonce"></param>
        public GCM(byte[] key = null, byte[] nonce = null)
        {
            if (key == null && nonce == null)
            {
                _key = new byte[KEY_BYTES];
                _nonce = new byte[NONCE_BYTES];
                RandomNumberGenerator.Fill(_key);
                RandomNumberGenerator.Fill(_nonce);
            } else
            {
                _key = key;
                _nonce = nonce;
            }
        }

        /// <summary>
        /// Encrypt given bytes
        /// </summary>
        /// <param name="toEncrypt"></param>
        /// <param name="key"></param>
        /// <param name="associatedData"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] toEncrypt, byte[] key, byte[] associatedData = null)
        {
            byte[] tag = new byte[KEY_BYTES];
            byte[] nonce = new byte[NONCE_BYTES];
            byte[] cipherText = new byte[toEncrypt.Length];

            using (var cipher = new AesGcm(key))
            {
                cipher.Encrypt(nonce, toEncrypt, cipherText, tag, associatedData);

                return Concat(tag, Concat(nonce, cipherText));
            }
        }

        /// <summary>
        /// Decrypt Given Bytes
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="associatedData"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] associatedData = null)
        {
            byte[] tag = SubArray(cipherText, 0, KEY_BYTES);
            byte[] nonce = SubArray(cipherText, KEY_BYTES, NONCE_BYTES);

            byte[] toDecrypt = SubArray(cipherText, KEY_BYTES + NONCE_BYTES, cipherText.Length - tag.Length - nonce.Length);
            byte[] decryptedData = new byte[toDecrypt.Length];

            using (var cipher = new AesGcm(key))
            {
                cipher.Decrypt(nonce, toDecrypt, tag, decryptedData, associatedData);

                return decryptedData;
            }
        }


        /// <summary>
        /// Concatening given array of bytes
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] output = new byte[a.Length + b.Length];

            for (int i = 0; i < a.Length; i++)
            {
                output[i] = a[i];
            }

            for (int j = 0; j < b.Length; j ++)
            {
                output[a.Length + j] = b[j];
            }

            return output;
        }

        /// <summary>
        /// Return subarray of bytes
        /// </summary>
        /// <param name="data"></param>
        /// <param name="start"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] SubArray(byte[] data, int start, int length)
        {
            byte[] result = new byte[length];

            Array.Copy(data, start, result, 0, length);

            return result;
        }

    }
}
