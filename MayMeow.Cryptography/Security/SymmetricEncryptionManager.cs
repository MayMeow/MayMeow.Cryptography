using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MayMeow.Cryptography.Security
{
    public static class SymmetricEncryptionManager
    {
        private const int keySize = 32;
        private const int IVSize = 16;
        private const int DefaultIterations = 100000;

        public class EncryptedData
        {
            public byte[] CipherData { get; set; }
            public byte[] Salt { get; set; }
            public byte[] IV { get; set; }
            public int Iterations { get; set; }
        }

        public static EncryptedData encryptData(string password, string DataToEncrypt)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty", nameof(password));
            }

            var IV = new byte[IVSize];
            var salt = new byte[IVSize];
            RandomNumberGenerator.Fill(IV);
            RandomNumberGenerator.Fill(salt);

            using (var pbkdf = new Rfc2898DeriveBytes(password, salt, DefaultIterations, HashAlgorithmName.SHA256)) {
                var derivedKey = pbkdf.GetBytes(keySize);

                using (var aes = Aes.Create())
                {
                    aes.Key = derivedKey;
                    aes.IV = IV;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        var dataBytes = Encoding.UTF8.GetBytes(DataToEncrypt);
                        var encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);

                        return new EncryptedData
                        {
                            CipherData = encryptedData,
                            Salt = salt,
                            IV = IV,
                            Iterations = DefaultIterations
                        };
                    }
                }
            }
        }

        public static string decryptData(EncryptedData encryptedData, string password)
        {
            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData), "Encrypted data cannot be null");
            }
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty", nameof(password));
            }
            using (var pbkdf = new Rfc2898DeriveBytes(password, encryptedData.Salt, encryptedData.Iterations, HashAlgorithmName.SHA256))
            {
                var derivedKey = pbkdf.GetBytes(keySize);
                using (var aes = Aes.Create())
                {
                    aes.Key = derivedKey;
                    aes.IV = encryptedData.IV;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    using (var decryptor = aes.CreateDecryptor())
                    {
                        var decryptedData = decryptor.TransformFinalBlock(encryptedData.CipherData, 0, encryptedData.CipherData.Length);
                        return Encoding.UTF8.GetString(decryptedData);
                    }
                }
            }
        }

        public static string GenerateRandomPassword()
        {
            var passwordBytes = new byte[keySize];
            RandomNumberGenerator.Fill(passwordBytes);
            return Convert.ToBase64String(passwordBytes);
        }
    }

    
}
