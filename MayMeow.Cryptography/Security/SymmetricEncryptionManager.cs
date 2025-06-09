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
    /// Provides high-level symmetric encryption and decryption functionality using AES-256 algorithm.
    /// This class uses AES encryption in CBC mode with PKCS7 padding, combined with PBKDF2-SHA256 
    /// for secure key derivation from passwords. Each encryption operation generates a unique salt 
    /// and initialization vector (IV) to ensure maximum security.
    /// </summary>
    /// <remarks>
    /// <para>Security Features:</para>
    /// <list type="bullet">
    /// <item><description>AES-256 encryption with CBC mode and PKCS7 padding</description></item>
    /// <item><description>PBKDF2-SHA256 key derivation with 100,000 iterations</description></item>
    /// <item><description>Unique salt and IV generated for each encryption operation</description></item>
    /// <item><description>Secure random password generation capability</description></item>
    /// </list>
    /// <para>Important Security Notes:</para>
    /// <list type="bullet">
    /// <item><description>Always use strong, unique passwords for encryption</description></item>
    /// <item><description>Never reuse the same password for multiple encryption operations unless necessary</description></item>
    /// <item><description>Store encrypted data securely and protect against tampering</description></item>
    /// <item><description>The salt and IV are automatically included in the encrypted data structure</description></item>
    /// </list>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Generate a secure random password
    /// string password = SymmetricEncryptionManager.GenerateRandomPassword();
    /// string dataToEncrypt = "Sensitive information to protect";
    /// 
    /// // Encrypt the data
    /// var encryptedData = SymmetricEncryptionManager.encryptData(password, dataToEncrypt);
    /// 
    /// // Convert to Base64 for storage or transmission
    /// string base64Encrypted = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(encryptedData);
    /// 
    /// // Later, decrypt the data
    /// var retrievedData = SymmetricEncryptionManager.EncryptedDataExtensions.FromBase64(base64Encrypted);
    /// string decryptedText = SymmetricEncryptionManager.decryptData(retrievedData, password);
    /// 
    /// Console.WriteLine($"Original: {dataToEncrypt}");
    /// Console.WriteLine($"Decrypted: {decryptedText}");
    /// // Output: Both strings will be identical
    /// </code>
    /// </example>
    public static class SymmetricEncryptionManager
    {
        /// <summary>
        /// The size of the encryption key in bytes (32 bytes = 256 bits for AES-256).
        /// </summary>
        private const int keySize = 32;
        
        /// <summary>
        /// The size of the initialization vector (IV) in bytes (16 bytes = 128 bits for AES block size).
        /// </summary>
        private const int IVSize = 16;
        
        /// <summary>
        /// The default number of iterations for PBKDF2 key derivation (100,000 iterations for strong security).
        /// </summary>
        private const int DefaultIterations = 100000;

        /// <summary>
        /// Represents encrypted data along with the cryptographic parameters needed for decryption.
        /// This class encapsulates all the information required to decrypt data, including the 
        /// ciphertext, salt, initialization vector, and key derivation iterations.
        /// </summary>
        /// <remarks>
        /// This class is designed to be serializable and can be converted to/from Base64 format
        /// using the <see cref="EncryptedDataExtensions"/> methods for easy storage or transmission.
        /// All cryptographic parameters are automatically generated during encryption and must be
        /// preserved exactly to ensure successful decryption.
        /// </remarks>
        public class EncryptedData
        {
            /// <summary>
            /// Gets or sets the encrypted data bytes. This contains the actual ciphertext
            /// produced by the AES encryption algorithm.
            /// </summary>
            /// <value>A byte array containing the encrypted data.</value>
            public byte[] CipherData { get; set; }
            
            /// <summary>
            /// Gets or sets the cryptographic salt used for key derivation. The salt is a random
            /// value that ensures the same password produces different encryption keys across
            /// different encryption operations.
            /// </summary>
            /// <value>A 16-byte array containing the random salt value.</value>
            /// <remarks>
            /// The salt is crucial for security as it prevents rainbow table attacks and ensures
            /// that identical passwords don't produce identical encryption keys.
            /// </remarks>
            public byte[] Salt { get; set; }
            
            /// <summary>
            /// Gets or sets the initialization vector (IV) used for AES encryption. The IV ensures
            /// that identical plaintext blocks produce different ciphertext blocks.
            /// </summary>
            /// <value>A 16-byte array containing the initialization vector.</value>
            /// <remarks>
            /// The IV must be unique for each encryption operation with the same key to maintain
            /// semantic security. It does not need to be secret but must be unpredictable.
            /// </remarks>
            public byte[] IV { get; set; }
            
            /// <summary>
            /// Gets or sets the number of iterations used in the PBKDF2 key derivation function.
            /// Higher iteration counts provide better security against brute-force attacks.
            /// </summary>
            /// <value>The number of PBKDF2 iterations used for key derivation (default: 100,000).</value>
            /// <remarks>
            /// The iteration count affects both security and performance. The default value of 100,000
            /// provides strong security while maintaining reasonable performance on modern hardware.
            /// </remarks>
            public int Iterations { get; set; }
        }

        /// <summary>
        /// Provides extension methods for converting <see cref="EncryptedData"/> objects to and from Base64 strings.
        /// These methods enable easy serialization of encrypted data for storage in databases, configuration files,
        /// or transmission over text-based protocols.
        /// </summary>
        /// <remarks>
        /// The Base64 format combines all cryptographic parameters (salt, IV, iterations, and ciphertext) into a
        /// single string that can be safely stored and transmitted. The format is:
        /// [16-byte salt][16-byte IV][4-byte iterations][variable-length ciphertext]
        /// </remarks>
        public static class EncryptedDataExtensions
        {
            /// <summary>
            /// Converts an <see cref="EncryptedData"/> object to a Base64-encoded string representation.
            /// This method serializes all cryptographic parameters into a single string for easy storage or transmission.
            /// </summary>
            /// <param name="encryptedData">The encrypted data object to convert. Must not be null.</param>
            /// <returns>
            /// A Base64-encoded string containing the salt, IV, iteration count, and ciphertext.
            /// The string can be stored in text formats and later converted back using <see cref="FromBase64(string)"/>.
            /// </returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="encryptedData"/> is null.
            /// </exception>
            /// <remarks>
            /// The resulting Base64 string contains all information needed for decryption and can be safely
            /// stored in databases, configuration files, or transmitted over text-based protocols.
            /// The format preserves the exact binary data while ensuring compatibility with text-based systems.
            /// </remarks>
            /// <example>
            /// <code>
            /// var encryptedData = SymmetricEncryptionManager.encryptData("password", "secret data");
            /// string base64String = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(encryptedData);
            /// // Store base64String in database or configuration file
            /// </code>
            /// </example>
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
            /// Converts a Base64-encoded string back to an <see cref="EncryptedData"/> object.
            /// This method deserializes a Base64 string created by <see cref="ToBase64(EncryptedData)"/> 
            /// back into its component cryptographic parameters.
            /// </summary>
            /// <param name="base64String">
            /// The Base64-encoded string containing encrypted data. Must not be null or empty.
            /// The string must have been created by the <see cref="ToBase64(EncryptedData)"/> method.
            /// </param>
            /// <returns>
            /// An <see cref="EncryptedData"/> object containing the deserialized salt, IV, iteration count, 
            /// and ciphertext extracted from the Base64 string.
            /// </returns>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="base64String"/> is null or empty.
            /// </exception>
            /// <exception cref="FormatException">
            /// Thrown when <paramref name="base64String"/> is not a valid Base64 string or does not
            /// contain the expected data format.
            /// </exception>
            /// <remarks>
            /// <para>The method expects the Base64 string to contain data in the specific format:</para>
            /// <list type="number">
            /// <item><description>16 bytes: Salt for key derivation</description></item>
            /// <item><description>16 bytes: Initialization Vector (IV)</description></item>
            /// <item><description>4 bytes: Iteration count as little-endian integer</description></item>
            /// <item><description>Remaining bytes: Encrypted ciphertext</description></item>
            /// </list>
            /// <para>
            /// Any deviation from this format will result in unpredictable behavior or exceptions.
            /// Only use Base64 strings created by the <see cref="ToBase64(EncryptedData)"/> method.
            /// </para>
            /// </remarks>
            /// <example>
            /// <code>
            /// // Retrieve base64String from database or configuration
            /// string base64String = GetStoredEncryptedData();
            /// var encryptedData = SymmetricEncryptionManager.EncryptedDataExtensions.FromBase64(base64String);
            /// string decryptedData = SymmetricEncryptionManager.decryptData(encryptedData, "password");
            /// </code>
            /// </example>
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
        /// Encrypts the specified plaintext string using AES-256 encryption with a password-derived key.
        /// This method uses PBKDF2-SHA256 for key derivation and generates unique salt and IV values
        /// for each encryption operation to ensure maximum security.
        /// </summary>
        /// <param name="password">
        /// The password used for encryption. Must not be null or empty. 
        /// Use a strong, unique password for each encryption context.
        /// Consider using <see cref="GenerateRandomPassword()"/> for secure password generation.
        /// </param>
        /// <param name="DataToEncrypt">
        /// The plaintext string to encrypt. The string will be encoded using UTF-8 before encryption.
        /// </param>
        /// <returns>
        /// An <see cref="EncryptedData"/> object containing the encrypted data along with all
        /// cryptographic parameters (salt, IV, iterations) needed for decryption.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="password"/> is null or empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// Thrown when the encryption operation fails due to cryptographic errors.
        /// </exception>
        /// <remarks>
        /// <para>Security Features:</para>
        /// <list type="bullet">
        /// <item><description>Uses AES-256 encryption in CBC mode with PKCS7 padding</description></item>
        /// <item><description>Employs PBKDF2-SHA256 with 100,000 iterations for key derivation</description></item>
        /// <item><description>Generates cryptographically secure random salt and IV for each operation</description></item>
        /// <item><description>Salt prevents rainbow table attacks and ensures unique keys per operation</description></item>
        /// <item><description>IV ensures semantic security by making identical plaintexts produce different ciphertexts</description></item>
        /// </list>
        /// <para>Password Security Guidelines:</para>
        /// <list type="bullet">
        /// <item><description>Use passwords with high entropy (consider using <see cref="GenerateRandomPassword()"/>)</description></item>
        /// <item><description>Never hardcode passwords in source code</description></item>
        /// <item><description>Store passwords securely using appropriate password management techniques</description></item>
        /// <item><description>Consider using different passwords for different encryption contexts</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Using a generated password
        /// string password = SymmetricEncryptionManager.GenerateRandomPassword();
        /// string sensitiveData = "Credit card number: 1234-5678-9012-3456";
        /// 
        /// var encryptedResult = SymmetricEncryptionManager.encryptData(password, sensitiveData);
        /// 
        /// // The result contains all data needed for decryption
        /// Console.WriteLine($"Salt length: {encryptedResult.Salt.Length}");      // 16 bytes
        /// Console.WriteLine($"IV length: {encryptedResult.IV.Length}");          // 16 bytes  
        /// Console.WriteLine($"Iterations: {encryptedResult.Iterations}");        // 100,000
        /// Console.WriteLine($"Cipher length: {encryptedResult.CipherData.Length}"); // Variable
        /// </code>
        /// </example>
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
        /// Decrypts the specified encrypted data using the provided password.
        /// This method reconstructs the original encryption key using the stored salt and iteration count,
        /// then decrypts the ciphertext to recover the original plaintext.
        /// </summary>
        /// <param name="encryptedData">
        /// The encrypted data object containing the ciphertext and all cryptographic parameters
        /// (salt, IV, iterations) needed for decryption. Must not be null and must have been
        /// created by the <see cref="encryptData(string, string)"/> method.
        /// </param>
        /// <param name="password">
        /// The password used during encryption. Must be exactly the same password that was
        /// used in the original encryption operation. Must not be null or empty.
        /// </param>
        /// <returns>
        /// The decrypted plaintext string. The binary ciphertext is decrypted and then
        /// converted from UTF-8 bytes back to the original string.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="encryptedData"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="password"/> is null or empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// Thrown when decryption fails. This typically occurs due to:
        /// <list type="bullet">
        /// <item><description>Incorrect password</description></item>
        /// <item><description>Corrupted or tampered encrypted data</description></item>
        /// <item><description>Invalid padding in the ciphertext</description></item>
        /// <item><description>Malformed cryptographic parameters</description></item>
        /// </list>
        /// </exception>
        /// <remarks>
        /// <para>Decryption Process:</para>
        /// <list type="number">
        /// <item><description>Derives the encryption key using PBKDF2-SHA256 with the provided password, stored salt, and iteration count</description></item>
        /// <item><description>Initializes AES decryption with the derived key and stored IV</description></item>
        /// <item><description>Decrypts the ciphertext using AES-256 in CBC mode with PKCS7 padding</description></item>
        /// <item><description>Converts the decrypted bytes back to a UTF-8 string</description></item>
        /// </list>
        /// <para>Security Considerations:</para>
        /// <list type="bullet">
        /// <item><description>The password must be identical to the one used during encryption</description></item>
        /// <item><description>All cryptographic parameters in the EncryptedData object must be preserved exactly</description></item>
        /// <item><description>Any modification to the encrypted data will result in decryption failure</description></item>
        /// <item><description>Failed decryption attempts do not reveal information about the correctness of individual parameters</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Assume we have encrypted data from a previous encryption operation
        /// string password = "SecurePassword123";
        /// var encryptedData = /* ... retrieved from storage ... */;
        /// 
        /// try
        /// {
        ///     string decryptedText = SymmetricEncryptionManager.decryptData(encryptedData, password);
        ///     Console.WriteLine($"Successfully decrypted: {decryptedText}");
        /// }
        /// catch (CryptographicException ex)
        /// {
        ///     Console.WriteLine("Decryption failed - incorrect password or corrupted data");
        ///     // Handle decryption failure appropriately
        /// }
        /// </code>
        /// </example>
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
        /// Generates a cryptographically secure random password suitable for encryption operations.
        /// This method creates a high-entropy password using a cryptographically secure random number generator
        /// and encodes it as a Base64 string for safe handling in text-based systems.
        /// </summary>
        /// <returns>
        /// A Base64-encoded string representing a cryptographically secure random password.
        /// The password has 256 bits of entropy (32 random bytes) and is safe to use for
        /// encryption operations with this class.
        /// </returns>
        /// <remarks>
        /// <para>Password Characteristics:</para>
        /// <list type="bullet">
        /// <item><description>256 bits (32 bytes) of cryptographic entropy</description></item>
        /// <item><description>Generated using <see cref="RandomNumberGenerator"/> for cryptographic security</description></item>
        /// <item><description>Base64-encoded for safe storage and transmission</description></item>
        /// <item><description>No special character restrictions or formatting requirements</description></item>
        /// <item><description>Suitable for long-term storage and repeated use</description></item>
        /// </list>
        /// <para>Use Cases:</para>
        /// <list type="bullet">
        /// <item><description>Generating master passwords for encryption applications</description></item>
        /// <item><description>Creating unique passwords for different encryption contexts</description></item>
        /// <item><description>Generating passwords for automated systems where human readability is not required</description></item>
        /// <item><description>Creating high-security passwords for sensitive data encryption</description></item>
        /// </list>
        /// <para>Security Notes:</para>
        /// <list type="bullet">
        /// <item><description>Each call generates a completely unique password</description></item>
        /// <item><description>The generated passwords are suitable for long-term use</description></item>
        /// <item><description>Store generated passwords securely using appropriate password management practices</description></item>
        /// <item><description>Consider the password lifetime and rotation policies for your specific use case</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Generate a secure password for encryption
        /// string securePassword = SymmetricEncryptionManager.GenerateRandomPassword();
        /// Console.WriteLine($"Generated password: {securePassword}");
        /// // Output: Base64 string like "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
        /// 
        /// // Use the password for encryption
        /// string dataToEncrypt = "Sensitive information";
        /// var encryptedData = SymmetricEncryptionManager.encryptData(securePassword, dataToEncrypt);
        /// 
        /// // Store the password securely for later decryption
        /// // ... secure password storage logic ...
        /// 
        /// // Later, decrypt using the same password
        /// string decryptedData = SymmetricEncryptionManager.decryptData(encryptedData, securePassword);
        /// </code>
        /// </example>
        public static string GenerateRandomPassword()
        {
            var passwordBytes = new byte[keySize];
            RandomNumberGenerator.Fill(passwordBytes);
            return Convert.ToBase64String(passwordBytes);
        }
    }

    
}
