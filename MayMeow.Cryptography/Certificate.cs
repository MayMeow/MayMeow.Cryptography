using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MayMeow.Cryptography
{
    public class Certificate
    {
        public static string OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
        public static string OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
        public static int KEY_SIZE = 4096;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="years"></param>
        /// <returns></returns>
        public static X509Certificate2 GenerateSelfSigned(string subjectName, int years = 1)
        {
            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(KEY_SIZE)) {
                CertificateRequest request = new CertificateRequest(
                    subjectName,
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(true, false, 0 ,true));

                request.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                return request.CreateSelfSigned(DateTime.UtcNow, DateTime.UtcNow.AddYears(years));
            };
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="signingCertificate"></param>
        /// <param name="keyUsageExtensions"></param>
        /// <param name="enhancedKeyUsageExtensions"></param>
        /// <returns></returns>
        public static X509Certificate2 SignCertificate(string subjectName, X509Certificate2 signingCertificate, X509KeyUsageExtension keyUsageExtensions, OidCollection enhancedKeyUsageExtensions)
        {
            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(4096))
            {
                CertificateRequest request = new CertificateRequest(
                    subjectName,
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));

                request.CertificateExtensions.Add(keyUsageExtensions);

                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        enhancedKeyUsageExtensions,
                        true));

                request.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                return request.Create(signingCertificate, DateTime.UtcNow, DateTime.UtcNow.AddDays(30), new byte[] { 1, 2, 3, 4 });
            }
        }
    }
}
