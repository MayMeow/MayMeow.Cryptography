using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace MayMeow.Cryptography
{
    public class RSA
    {
        private RSACryptoServiceProvider _provider;

        public static int KEY_SIZE = 4096;

        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public RSA(int keySize)
        {
            _provider = new RSACryptoServiceProvider(keySize);

            _publicKey = _provider.ExportParameters(false);
            _privateKey = _provider.ExportParameters(true);
        }

        /// <summary>
        /// Returns RSA parameters as string
        /// </summary>
        /// <returns></returns>
        public string GetPrivateKey()
        {
            StringWriter sw = new StringWriter();
            XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));

            xs.Serialize(sw, _privateKey);

            return sw.ToString();
        }

        /// <summary>
        /// Retursn RSA parameters as string
        /// </summary>
        /// <returns></returns>
        public string GetPublicKey()
        {
            StringWriter sw = new StringWriter();
            XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));

            xs.Serialize(sw, _publicKey);

            return sw.ToString();
        }

        /// <summary>
        /// Returns RSA Parameters
        /// </summary>
        /// <param name="withPrivateKey"></param>
        /// <returns></returns>
        public  RSAParameters GetRSAParameters(bool withPrivateKey = false)
        {
            if (withPrivateKey)
            {
                return _privateKey;
            }

            return _publicKey;
        }

        public static RSAParameters SetKeyFromString(string rsaKey)
        {
            string rsaKeyString = TextConversion.Base64Decode(rsaKey);

            StringReader sr = new StringReader(rsaKeyString);
            XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));

            RSAParameters rsaKeyParam = (RSAParameters)xs.Deserialize(sr);

            return rsaKeyParam;
        }

        /// <summary>
        /// Get keys from Certificate
        /// </summary>
        /// <param name="rSACryptoServiceProvider"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static RSAParameters SetKeyFromCertificate(RSACryptoServiceProvider rSACryptoServiceProvider, bool privateKey = false)
        {
            return rSACryptoServiceProvider.ExportParameters(privateKey);
        }

        public static RSAParameters SetKeyFromXml(string xmlString, bool privateKey = false)
        {
            RSACryptoServiceProvider rSA = new RSACryptoServiceProvider(4096);
            rSA.FromXmlString(xmlString);

            return rSA.ExportParameters(privateKey);
        }

        /// <summary>
        /// Encrypt given plain text
        /// </summary>
        /// <param name="PlainText"></param>
        /// <returns></returns>
        public static string Encrypt(string PlainText, RSAParameters rsaKey)
        {
            byte[] data = Encoding.Unicode.GetBytes(PlainText);

            var cipher = EncryptBytes(data, rsaKey);

            return Convert.ToBase64String(cipher, Base64FormattingOptions.InsertLineBreaks);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="rsaKey"></param>
        /// <returns></returns>
        public static byte[] EncryptBytes(byte [] dataToEncrypt, RSAParameters rsaKey)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportParameters(rsaKey);

            byte[] cipher = provider.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA1);

            return cipher;
        }

        /// <summary>
        /// Decrypt encrypted text
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string Decrypt(string cipherText, RSAParameters rsaKey)
        {
            byte[] dataBytes = Convert.FromBase64String(cipherText);
            byte[] plainText = DecryptBytes(dataBytes, rsaKey);

            return Encoding.Unicode.GetString(plainText);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dataToDecrypt"></param>
        /// <param name="rsaKey"></param>
        /// <returns></returns>
        public static byte[] DecryptBytes(byte[] dataToDecrypt, RSAParameters rsaKey)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportParameters(rsaKey);

            byte[] decrypted = provider.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA1);

            return decrypted;
        }

        /// <summary>
        /// Signing given data
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <param name="rsaKey"></param>
        /// <returns></returns>
        public static byte[] HashAndSignBytes(byte[] dataToSign, RSAParameters rsaKey)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportParameters(rsaKey);

            return provider.SignData(dataToSign, SHA256.Create());
        }

        /// <summary>
        /// Verify Signed data
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="signedData"></param>
        /// <param name="rsaKey"></param>
        /// <returns></returns>
        public static bool VerifySignedHash(byte[] dataToVerify, byte[] signedData, RSAParameters rsaKey)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportParameters(rsaKey);

            return provider.VerifyData(dataToVerify, SHA256.Create(), signedData);
        }
    }
}
