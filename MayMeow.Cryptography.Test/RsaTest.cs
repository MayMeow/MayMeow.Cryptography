using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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
        public void TestEncryptAndDecrypt()
        {
            RSA rsa = new RSA(RSA.KEY_SIZE);

            string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
            string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());

            string message = "Hello world";
            string encryptedText = RSA.Encrypt(message, RSA.SetKeyFromString(pubKey));
            string plainText = RSA.Decrypt(encryptedText, RSA.SetKeyFromString(privKey));

            Assert.AreEqual(message, plainText);
        }

        [TestMethod]
        public void TestSignAndVerify()
        {
            RSA rsa = new RSA(RSA.KEY_SIZE);

            // Set keys from string
            // string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
            // string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());

            // get keys
            RSAParameters key = rsa.GetRSAParameters(true);

            string message = "Hello world";
            byte[] dataToSign = Encoding.Unicode.GetBytes(message);

            string modifiedMessage = message + "123";
            byte[] modifiedDataToVerify = Encoding.Unicode.GetBytes(modifiedMessage);

            byte[] signedData = RSA.HashAndSignBytes(dataToSign, key);

            Assert.AreEqual(true, RSA.VerifySignedHash(dataToSign, signedData, key));
            Assert.AreEqual(false, RSA.VerifySignedHash(modifiedDataToVerify, signedData, key));
        }

    }
}
