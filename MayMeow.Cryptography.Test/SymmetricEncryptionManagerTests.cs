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
    }
}
