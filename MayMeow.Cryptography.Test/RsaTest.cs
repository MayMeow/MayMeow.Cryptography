using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace MayMeow.Cryptography.Test
{
    [TestClass]
    public class RsaTest
    {
        [TestMethod]
        public void TestInitialization()
        {
            RSA rsa = new RSA(RSA.KEY_SIZE);

            Assert.IsInstanceOfType(rsa, typeof(RSA));
        }

        [TestMethod]
        public void TestKeysGenerating()
        {
            RSA rsa = new RSA(RSA.KEY_SIZE);

            string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
            string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());

            string message = "Hello world";
            string encryptedText = RSA.Encrypt(message, RSA.SetKeyFromString(pubKey));
            string plainText = RSA.Decrypt(encryptedText, RSA.SetKeyFromString(privKey));

            Assert.AreEqual(message, plainText);
        }

    }
}
