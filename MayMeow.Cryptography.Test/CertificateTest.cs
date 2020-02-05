using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MayMeow.Cryptography.Test
{
    [TestClass]
    public class CertificateTest
    {
        [TestMethod]
        public void SelfSignedCertificateTest()
        {
            string subject = "CN=Test Certificate, O=Org";

            var cert = Certificate.GenerateSelfSigned(subject);
            Assert.IsInstanceOfType(cert, typeof(X509Certificate2));
            Assert.AreEqual(cert.Subject, subject);
            Assert.IsTrue(cert.HasPrivateKey);

            // Export private and public key for CryptoServiceProvider
            System.Security.Cryptography.RSA priv = (System.Security.Cryptography.RSA)cert.PrivateKey;
            System.Security.Cryptography.RSA pub = (System.Security.Cryptography.RSA)cert.PublicKey.Key;

            string message = "Hello world";
            string encryptedText = RSA.Encrypt(message, pub.ExportParameters(false));
            string plainText = RSA.Decrypt(encryptedText, priv.ExportParameters(true));

            Assert.AreEqual(message, plainText);
        }

        [TestMethod]
        public void SignCertificateTest()
        {
            string caSubject = "CN=CA";
            var caCert = Certificate.GenerateSelfSigned(caSubject);

            string clientSubject = "CN=Client";
            var keyUsage = new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DataEncipherment,
                false);

            var enhancedKeyUsage = new OidCollection {
                new Oid(Certificate.OID_CODE_SIGNING),
                new Oid(Certificate.OID_TIME_STAMPING)
            };

            var clientCert = Certificate.SignCertificate(clientSubject, caCert, keyUsage, enhancedKeyUsage);

            Assert.IsInstanceOfType(clientCert, typeof(X509Certificate2));
            Assert.AreEqual(clientCert.Subject, clientSubject);
            //Assert.IsTrue(clientCert.HasPrivateKey);
        }
    }
}
