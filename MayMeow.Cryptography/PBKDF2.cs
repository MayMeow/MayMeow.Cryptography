using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace MayMeow.Cryptography
{
    public class PBKDF2
    {
        /// <summary>
        ///  PBKDF2 can be used to derivate cryptography key from password.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="iterationCount"></param>
        /// <param name="keyLenghtBytes"></param>
        /// <returns></returns>
        public static string keyDerivate(string password, string salt, int iterationCount = 1024, int keyLenghtBytes = 256)
        {
            var key = KeyDerivation.Pbkdf2(password, System.Text.Encoding.UTF8.GetBytes(salt), KeyDerivationPrf.HMACSHA256, iterationCount, keyLenghtBytes);

            return System.Text.Encoding.UTF8.GetString(key);
        }
    }
}
