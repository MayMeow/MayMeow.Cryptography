using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using MayMeow.Cryptography;

namespace MayMeow.Cryptography.Test
{
    [TestClass]
    public class Pbkdf2KeyDerivationTest
    {
        [TestMethod]
        public void KeyDerivation()
        {
            // Set variables
            string password = "my$up3r$3cr3tP4$$w0rd1";
            string salt = "8VySCxa42j9McSqGjZxCVQnH4x4rSZszEL9YQT3VkZ75xbBD";
            string requestedKey = "Vu+/ve+/ve+/vWfvv71d77+9Ou+/vQ==";

            // get your derived key
            var derivedKey = PBKDF2.keyDerivate(password, salt, 1024, 10);

            // I converting this to base64 to compare if keys are equal.
            Assert.AreEqual(requestedKey, TextConversion.Base64Encode(derivedKey));
        }
    }
}
