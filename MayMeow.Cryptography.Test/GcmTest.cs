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
            // Create RSA Keys
            RSA rsa = new RSA(RSA.KEY_SIZE);

            string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
            string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());

            byte[] dataToEncrypt = new byte[300];
            RandomNumberGenerator.Fill(dataToEncrypt);

            // Create AES Keys
            byte[] key = new byte[16];
            RandomNumberGenerator.Fill(key);

            byte[] aad = new byte[32];
            RandomNumberGenerator.Fill(aad);

            // SECURE GCM Key
            // Encrypt Key for AES with RSA and check if given and decrypted keys are equal
            byte[] encryptedAeskey = RSA.EncryptBytes(key, RSA.SetKeyFromString(pubKey));
            byte[] decryptedAesKey = RSA.DecryptBytes(encryptedAeskey, RSA.SetKeyFromString(privKey));
            Assert.IsTrue(key.SequenceEqual(decryptedAesKey));

            // ENCRYPT DATA
            // Encrypt with key and decrypt with DecryptedAesKey
            byte[] encryptedData = GCM.Encrypt(dataToEncrypt, key, aad);
            byte[] decryptedData = GCM.Decrypt(encryptedData, decryptedAesKey, aad);

            Assert.IsTrue(dataToEncrypt.SequenceEqual(decryptedData));

            string stringToEncrypt = "Ahoj svet";

            byte[] encryptedStringData = GCM.Encrypt(Encoding.UTF8.GetBytes(stringToEncrypt), key, aad);
            byte[] decryptedStringData = GCM.Decrypt(encryptedStringData, decryptedAesKey, aad);

            Assert.AreEqual(stringToEncrypt, Encoding.UTF8.GetString(decryptedStringData));
        }
    }
}
