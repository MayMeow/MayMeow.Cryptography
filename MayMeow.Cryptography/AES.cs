using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MayMeow.Cryptography
{
    public class AES
    {
        private SymmetricAlgorithm _Aes;

        public AES()
        {
            _Aes = new AesCryptoServiceProvider();
            _Aes.KeySize = 256;
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

        public static string Encrypt<T>(string plainText, string Key, string IV) where T : SymmetricAlgorithm, new()
        {
            byte[] encrypted;

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
            }

            return Convert.ToBase64String(encrypted); ;
        }

        public static string Decrypt<T>(string encryptedText, string Key, string IV) where T : SymmetricAlgorithm, new()
        {
            string plainTest;
            byte[] ciperText = Convert.FromBase64String(encryptedText);

            using (T cipher = new T())
            {
                cipher.Key = System.Convert.FromBase64String(Key);
                cipher.IV = System.Convert.FromBase64String(IV);
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

        public static string Decrypt(string encryptedText, string Key, string IV)
        {
            return Decrypt<AesCryptoServiceProvider>(encryptedText, Key, IV);
        }
    }
}
