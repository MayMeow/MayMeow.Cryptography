using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MayMeow.Cryptography.Test
{
    [TestClass]
    public class EcdsaTest
    {
        [TestMethod]
        public void SigningTest()
        {
            ECDSA eCDSA = new ECDSA();
            ECParameters ecParameters = eCDSA.getKeys();

            string dataToSign = "Hello World!";

            byte[] signature = ECDSA.SignBytes(Encoding.UTF8.GetBytes(dataToSign), ecParameters);

            bool isVerified = ECDSA.VerifyBytes(Encoding.UTF8.GetBytes(dataToSign), signature, ecParameters);

            Assert.IsTrue(isVerified);
        }

        [TestMethod]
        public void TestKDF()
        {
            ECDSA eCDSA = new ECDSA();
            ECParameters ecParameters = eCDSA.getKeys();

            string keyOne = ECDSA.DeriveKey(ecParameters);
            string keyTwo = ECDSA.DeriveKey(ecParameters);

            Assert.AreEqual(keyOne, keyTwo);
        }
    }
}
