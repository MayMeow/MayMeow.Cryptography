using Microsoft.VisualStudio.TestTools.UnitTesting;
using MayMeow.Cryptography.Security;
using System;
using System.Text;
using System.Security.Cryptography;

namespace MayMeow.Cryptography.Test
{
    [TestClass]
    public class SymmetricEncryptionManagerTests
    {
        [TestMethod]
        public void EncryptData_ValidInput_ReturnsEncryptedData()
        {
            // Arrange  
            string password = SymmetricEncryptionManager.GenerateRandomPassword();
            string dataToEncrypt = "TestData";

            // Act  
            var encryptedData = SymmetricEncryptionManager.encryptData(password, dataToEncrypt);

            // Assert  
            Assert.IsNotNull(encryptedData);
            Assert.IsNotNull(encryptedData.CipherData);
            Assert.IsNotNull(encryptedData.Salt);
            Assert.IsNotNull(encryptedData.IV);
            Assert.AreEqual(100000, encryptedData.Iterations);
        }

        [TestMethod]
        public void DecryptData_ValidInput_ReturnsOriginalData()
        {
            // Arrange  
            string password = SymmetricEncryptionManager.GenerateRandomPassword();
            string dataToEncrypt = "TestData";
            var encryptedData = SymmetricEncryptionManager.encryptData(password, dataToEncrypt);

            // Act  
            var decryptedData = SymmetricEncryptionManager.decryptData(encryptedData, password);

            // Assert  
            Assert.AreEqual(dataToEncrypt, decryptedData);
        }

        [TestMethod]
        public void EncryptData_NullPassword_ThrowsArgumentException()
        {
            // Arrange  
            string password = null;
            string dataToEncrypt = "TestData";

            // Act & Assert  
            var ex = Assert.ThrowsException<ArgumentException>(() => SymmetricEncryptionManager.encryptData(password, dataToEncrypt));
            Assert.AreEqual("Password cannot be null or empty (Parameter 'password')", ex.Message);
        }

        [TestMethod]
        public void DecryptData_NullEncryptedData_ThrowsArgumentNullException()
        {
            // Arrange  
            string password = SymmetricEncryptionManager.GenerateRandomPassword();
            SymmetricEncryptionManager.EncryptedData encryptedData = null;

            // Act & Assert  
            var ex = Assert.ThrowsException<ArgumentNullException>(() => SymmetricEncryptionManager.decryptData(encryptedData, password));
            Assert.AreEqual("Encrypted data cannot be null (Parameter 'encryptedData')", ex.Message);
        }

        [TestMethod]
        public void DecryptData_InvalidPassword_ThrowsCryptographicException()
        {
            // Arrange  
            string password = SymmetricEncryptionManager.GenerateRandomPassword();
            string dataToEncrypt = "TestData";
            var encryptedData = SymmetricEncryptionManager.encryptData(password, dataToEncrypt);
            string invalidPassword = "WrongPassword";

            // Act & Assert  
            Assert.ThrowsException<CryptographicException>(() => SymmetricEncryptionManager.decryptData(encryptedData, invalidPassword));
        }

        [TestMethod]
        public void EncryptedDataExtensions_ToBase64_ShouldReturnValidBase64String()
        {
            // Arrange  
            var encryptedData = new SymmetricEncryptionManager.EncryptedData
            {
                Salt = new byte[16],
                IV = new byte[16],
                Iterations = 100000,
                CipherData = new byte[32]
            };

            // Act  
            var base64String = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(encryptedData);

            // Assert  
            Assert.IsFalse(string.IsNullOrEmpty(base64String));
        }

        [TestMethod]
        public void EncryptedDataExtensions_FromBase64_ShouldReturnValidEncryptedData()
        {
            // Arrange  
            var encryptedData = new SymmetricEncryptionManager.EncryptedData
            {
                Salt = new byte[16],
                IV = new byte[16],
                Iterations = 100000,
                CipherData = new byte[32]
            };
            var base64String = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(encryptedData);

            // Act  
            var result = SymmetricEncryptionManager.EncryptedDataExtensions.FromBase64(base64String);

            // Assert  
            Assert.IsNotNull(result);
            CollectionAssert.AreEqual(encryptedData.Salt, result.Salt);
            CollectionAssert.AreEqual(encryptedData.IV, result.IV);
            Assert.AreEqual(encryptedData.Iterations, result.Iterations);
            CollectionAssert.AreEqual(encryptedData.CipherData, result.CipherData);
        }

        [TestMethod]
        public void EncryptData_ValidInput_ReturnsEncryptedData_ToBase64()
        {
            // Arrange  
            string password = SymmetricEncryptionManager.GenerateRandomPassword();
            string dataToEncrypt = "TestData";

            // Act  
            string encryptedString = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(SymmetricEncryptionManager.encryptData(password, dataToEncrypt));

            var encryptedData = SymmetricEncryptionManager.EncryptedDataExtensions.FromBase64(encryptedString);

            // Assert  
            Assert.IsNotNull(encryptedData);
            Assert.IsNotNull(encryptedData.CipherData);
            Assert.IsNotNull(encryptedData.Salt);
            Assert.IsNotNull(encryptedData.IV);
            Assert.AreEqual(100000, encryptedData.Iterations);
        }

        [TestMethod]
        public void DecryptData_ValidInput_ReturnsOriginalData_FromBase64()
        {
            // Arrange  
            string password = SymmetricEncryptionManager.GenerateRandomPassword();
            string dataToEncrypt = "TestData";
            string encryptedString = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(SymmetricEncryptionManager.encryptData(password, dataToEncrypt));

            // Act  
            var decryptedData = SymmetricEncryptionManager.decryptData(SymmetricEncryptionManager.EncryptedDataExtensions.FromBase64(encryptedString), password);

            // Assert  
            Assert.AreEqual(dataToEncrypt, decryptedData);
        }
    }
}
