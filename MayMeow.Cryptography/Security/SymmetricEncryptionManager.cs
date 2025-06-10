using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MayMeow.Cryptography.Security
{
    /// <summary>
    /// Provides symmetric encryption and decryption using AES-256 with PBKDF2 key derivation.
    /// </summary>
    public static class SymmetricEncryptionManager
    {
        private const int keySize = 32;
        private const int IVSize = 16;
        private const int DefaultIterations = 100000;

        /// <summary>
        /// Contains encrypted data and cryptographic parameters needed for decryption.
        /// </summary>
        public class EncryptedData
        {
            /// <summary>
            /// Gets or sets the encrypted data bytes.
            /// </summary>
            public byte[] CipherData { get; set; }
            
            /// <summary>
            /// Gets or sets the salt used for key derivation.
            /// </summary>
            public byte[] Salt { get; set; }
            
            /// <summary>
            /// Gets or sets the initialization vector used for encryption.
            /// </summary>
            public byte[] IV { get; set; }
            
            /// <summary>
            /// Gets or sets the number of PBKDF2 iterations used for key derivation.
            /// </summary>
            public int Iterations { get; set; }
        }

        /// <summary>
        /// Provides conversion methods for EncryptedData objects.
        /// </summary>
        public static class EncryptedDataExtensions
        {
            /// <summary>
            /// Converts EncryptedData to a Base64 string for storage or transmission.
            /// </summary>
            /// <param name="encryptedData">The encrypted data to convert.</param>
            /// <returns>A Base64 string representation of the encrypted data.</returns>
            /// <exception cref="ArgumentNullException">Thrown when encryptedData is null.</exception>
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

            /// <summary>
            /// Converts a Base64 string back to EncryptedData object.
            /// </summary>
            /// <param name="base64String">The Base64 string to convert.</param>
            /// <returns>An EncryptedData object containing the cryptographic parameters.</returns>
            /// <exception cref="ArgumentException">Thrown when base64String is null or empty.</exception>
            /// <exception cref="FormatException">Thrown when base64String is not a valid Base64 string.</exception>
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

        /// <summary>
        /// Encrypts data using AES-256 encryption with PBKDF2 key derivation.
        /// </summary>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="DataToEncrypt">The data to encrypt.</param>
        /// <returns>An EncryptedData object containing the encrypted data and cryptographic parameters.</returns>
        /// <exception cref="ArgumentException">Thrown when password is null or empty.</exception>
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

        /// <summary>
        /// Decrypts data using the provided password and encrypted data parameters.
        /// </summary>
        /// <param name="encryptedData">The encrypted data to decrypt.</param>
        /// <param name="password">The password used for decryption.</param>
        /// <returns>The decrypted data as a string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when encryptedData is null.</exception>
        /// <exception cref="ArgumentException">Thrown when password is null or empty.</exception>
        /// <exception cref="CryptographicException">Thrown when decryption fails.</exception>
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

        /// <summary>
        /// Generates a cryptographically secure random password.
        /// </summary>
        /// <returns>A Base64-encoded random password with 256 bits of entropy.</returns>
        public static string GenerateRandomPassword()
        {
            var passwordBytes = new byte[keySize];
            RandomNumberGenerator.Fill(passwordBytes);
            return Convert.ToBase64String(passwordBytes);
        }
    }

    
}
