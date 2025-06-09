using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MayMeow.Cryptography
{

    /// <summary>
    /// AES encryption and decryption class using AesCryptoServiceProvider.
    /// </summary>
    /// 
    [Obsolete("This class is deprecated, see MayMeow.Cryptography.Security.SymmetricEncryptionManager Instead")]
    public class AES
    {
        private SymmetricAlgorithm _Aes;
        public static int AES_KEY_SIZE = 256;

        public AES()
        {
            _Aes = new AesCryptoServiceProvider();
            _Aes.KeySize = AES_KEY_SIZE;
            _Aes.GenerateKey();
            _Aes.GenerateIV();
        }

        public string GetAesKey()
        {
            return System.Convert.ToBase64String(_Aes.Key);
        }

        public string GetIV()
        {
            return System.Convert.ToBase64String(_Aes.IV);
        }

        /// <summary>
        /// Return encrypted data IV + Data
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="plainText"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public static string Encrypt<T>(string plainText, string Key, string IV) where T : SymmetricAlgorithm, new()
        {
            byte[] encrypted;
            byte[] encryptedData;

            using (T cipher = new T())
            {
                cipher.Key = System.Convert.FromBase64String(Key);
                cipher.IV = System.Convert.FromBase64String(IV);
                cipher.Mode = CipherMode.CBC;

                ICryptoTransform encryptor = cipher.CreateEncryptor(cipher.Key, cipher.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }

                        encrypted = ms.ToArray();
                    }
                }

                encryptedData = GCM.Concat(cipher.IV, encrypted);
            }

            

            return Convert.ToBase64String(encryptedData); ;
        }

        /// <summary>
        /// Decrypt data IV + DATA with given key
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="encryptedText"></param>
        /// <param name="Key"></param>
        /// <returns></returns>
        public static string Decrypt<T>(string encryptedText, string Key) where T : SymmetricAlgorithm, new()
        {
            AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
            byte[] IV = new byte[aesCryptoServiceProvider.BlockSize / 8];

            string plainTest;
            byte[] ciperData = Convert.FromBase64String(encryptedText);
            byte[] ciperText = GCM.SubArray(ciperData, IV.Length, ciperData.Length - IV.Length);

            using (T cipher = new T())
            {
                cipher.Key = System.Convert.FromBase64String(Key);
                cipher.IV = GCM.SubArray(ciperData, 0, IV.Length);
                cipher.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = cipher.CreateDecryptor(cipher.Key, cipher.IV);

                using (MemoryStream ms = new MemoryStream(ciperText))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            plainTest = sr.ReadToEnd();
                        }
                    }
                }

            }

            return plainTest;
        }

        public static string Encrypt(string plainText, string Key, string IV)
        {
            return Encrypt<AesCryptoServiceProvider>(plainText, Key, IV);
        }

        public static string Decrypt(string encryptedText, string Key)
        {
            return Decrypt<AesCryptoServiceProvider>(encryptedText, Key);
        }
    }
}
