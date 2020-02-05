using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MayMeow.Cryptography.Test
{
    [TestClass]
    public class GcmTest
    {
        [TestMethod]
        public void EncryptionTest()
        {
            byte[] dataToEncrypt = new byte[300];
            RandomNumberGenerator.Fill(dataToEncrypt);

            byte[] key = new byte[16];
            RandomNumberGenerator.Fill(key);

            byte[] aad = new byte[32];
            RandomNumberGenerator.Fill(aad);

            byte[] encryptedData = GCM.Encrypt(dataToEncrypt, key, aad);

            byte[] decryptedData = GCM.Decrypt(encryptedData, key, aad);

            Assert.IsTrue(dataToEncrypt.SequenceEqual(decryptedData));

            string stringToEncrypt = "Ahoj svet";

            byte[] encryptedStringData = GCM.Encrypt(Encoding.UTF8.GetBytes(stringToEncrypt), key, aad);
            byte[] decryptedStringData = GCM.Decrypt(encryptedStringData, key, aad);

            Assert.AreEqual(stringToEncrypt, Encoding.UTF8.GetString(decryptedStringData));
        }
    }
}
