using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace MayMeow.Cryptography.Test
{
    [TestClass]
    public class AesTest
    {
        [TestMethod]
        public void TestEncryption()
        {
            AES aes = new AES();

            string AesKey = aes.GetAesKey();
            string AesIV = aes.GetIV();

            string message = "Hello world";
            string AesEncrypted = AES.Encrypt(message, AesKey, AesIV);
            string AesDecrypted = AES.Decrypt(AesEncrypted, AesKey, AesIV);

            Assert.AreEqual(message, AesDecrypted);
        }

    }
}
