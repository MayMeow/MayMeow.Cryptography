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

        public static class EncryptedDataExtensions
        {
            public static string ToBase64(EncryptedData encryptedData)
            {
                if (encryptedData == null)
                {
                    throw new ArgumentNullException(nameof(encryptedData), "Encrypted data cannot be null");
                }

                var combinedData = new List<byte>();
                combinedData.AddRange(encryptedData.Salt);
                combinedData.AddRange(encryptedData.IV);
                combinedData.AddRange(BitConverter.GetBytes(encryptedData.Iterations));
                combinedData.AddRange(encryptedData.CipherData);

                return Convert.ToBase64String(combinedData.ToArray());
            }

            public static EncryptedData FromBase64(string base64String)
            {
                if (string.IsNullOrEmpty(base64String))
                {
                    throw new ArgumentException("Base64 string cannot be null or empty", nameof(base64String));
                }

                var combinedData = Convert.FromBase64String(base64String);

                var salt = combinedData.Take(16).ToArray();
                var iv = combinedData.Skip(16).Take(16).ToArray();
                var iterations = BitConverter.ToInt32(combinedData.Skip(32).Take(4).ToArray(), 0);
                var cipherData = combinedData.Skip(36).ToArray();

                return new EncryptedData
                {
                    Salt = salt,
                    IV = iv,
                    Iterations = iterations,
                    CipherData = cipherData
                };
            }
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
