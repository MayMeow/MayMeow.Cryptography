using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace MayMeow.Cryptography
{
    public class ECDSA
    {

        protected ECDsa eCDsa;

        protected ECParameters ecParameters;

        public ECDSA()
        {
            using (eCDsa = ECDsa.Create())
            {
                eCDsa.GenerateKey(ECCurve.NamedCurves.nistP256);
                ecParameters = eCDsa.ExportParameters(true);
            }
        }

        public string getPrivateKey()
        {
            return createXML(eCDsa.ExportParameters(true));
        }

        public string getPublicKey()
        {
            return createXML(eCDsa.ExportParameters(false));
        }

        private string createXML<T>(T parameters)
        {
            StringWriter sw = new StringWriter();
            XmlSerializer xs = new XmlSerializer(typeof(T));
            xs.Serialize(sw, parameters);

            return sw.ToString();
        }

        /// <summary>
        /// Return public and private key parameters
        /// </summary>
        /// <returns></returns>
        public ECParameters getKeys()
        {
            return ecParameters;
        }

        /// <summary>
        /// Sign data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static byte[] SignBytes(byte[] data , ECParameters parameters)
        {
            ECDsa ecvsaSigner = ECDsa.Create();
            byte[] signature;

            using (ecvsaSigner)
            {
                ecvsaSigner.ImportParameters(parameters);
                signature = ecvsaSigner.SignData(data, HashAlgorithmName.SHA256);
                
            }

            return signature;
        }

        /// <summary>
        /// Verify signed data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static bool VerifyBytes(byte[] data, byte[] signature, ECParameters parameters)
        {
            ECDsa ecvsaSigner = ECDsa.Create();
            bool isVerified;

            using (ecvsaSigner)
            {
                ecvsaSigner.ImportParameters(parameters);
                isVerified = ecvsaSigner.VerifyData(data, signature, HashAlgorithmName.SHA256);

            }

            return isVerified;
        }

        /// <summary>
        /// Derive key for symetric encryption
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public static string DeriveKey(ECParameters parameters, string context = "default_context")
        {
            byte[] privateKeyBytes = parameters.D;

            using (HMACSHA256 hmac =  new HMACSHA256(privateKeyBytes))
            {
                byte[] contextBytes = Encoding.UTF8.GetBytes(context);
                byte[] hash = hmac.ComputeHash(contextBytes);

                return Convert.ToBase64String(hash);
            }
        }

    }

}
