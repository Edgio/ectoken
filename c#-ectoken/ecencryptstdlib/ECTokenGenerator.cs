using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ecencryptstdlib
{
    /// <summary>
    /// ECTokenGenerator for .NET Standard Library 1.4
    /// ported and extended by Andreas Pollak (SpectoLogic)
    /// </summary>
    public class ECTokenGenerator
    {
        private static readonly SecureRandom Random = new SecureRandom();
        private readonly Random _rand = new Random((int)DateTime.Now.Ticks);
        private readonly int MIN_RANDOM_LENGTH = 4;
        private readonly int MAX_RANDOM_LENGTH = 8;
        private readonly char[] PADDING = { '=' };
        //Preconfigured Encryption Parameters
        public readonly int NonceBitSize = 96;
        public readonly int MacBitSize = 128;
        public readonly int KeyBitSize = 256;

        public string NextRandomString(int length)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[length];

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[_rand.Next(chars.Length)];
            }

            string randomString = new String(stringChars);
            return randomString;
        }

        public string NextRandomString()
        {
            int length = _rand.Next(MIN_RANDOM_LENGTH, MAX_RANDOM_LENGTH);
            return NextRandomString(length);
        }

        /// <summary>
        /// This helper methods allows to create expiring CDN encryption tokens
        /// https://docs.microsoft.com/en-us/azure/cdn/cdn-token-auth
        /// </summary>
        /// <param name="key">Encyption Secret</param>
        /// <param name="expirationTimeSpan">Timespan from UTCNow when token should expire</param>
        /// <param name="clientIPAddress">restricts access to specified requester's IP address. Both IPV4 and IPV6 are supported. You can specify single request IP address or IP subnet Example: "13.141.12.2/20" </param>
        /// <param name="allowedCountries">Comma separated list or null, Example: "US,FR" </param>
        /// <param name="deniedCountries">Comma separated list of countries you want to block or null, Example: "US,FR" </param>
        /// <param name="allowedReferrers">Comma separated list of allowed referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="deniedReferrers">Comma separated list of denied referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="allowedProtocol">Only allows requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="deniedProtocol">Denies requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="allowedUrls">allows you to tailor tokens to a particular asset or path. It restricts access to requests whose URL start with a specific relative path. You can input multiple paths separating each path with a comma. URLs are case-sensitive. Depending on the requirement, you can set up different value to provide different level of access</param>
        /// <returns></returns>
        public string EncryptV3(string key,
            TimeSpan expirationTimeSpan,
            string clientIPAddress = null,
            string allowedCountries = null,
            string deniedCountries = null,
            string allowedReferrers = null,
            string deniedReferrers = null,
            string allowedProtocol = null,
            string deniedProtocol = null,
            string allowedUrls = null)
        {
            DateTime expTime = DateTime.UtcNow + expirationTimeSpan;
            return EncryptV3(key, expTime, clientIPAddress, allowedCountries, deniedCountries, allowedReferrers, deniedReferrers,
                allowedProtocol, deniedProtocol);
        }
        /// <summary>
        /// This helper methods allows to create expiring CDN encryption tokens
        /// https://docs.microsoft.com/en-us/azure/cdn/cdn-token-auth
        /// </summary>
        /// <param name="key">Encyption Secret</param>
        /// <param name="expirationTimeSpan">Absolute time when token should expire</param>
        /// <param name="clientIPAddress">restricts access to specified requester's IP address. Both IPV4 and IPV6 are supported. You can specify single request IP address or IP subnet Example: "13.141.12.2/20" </param>
        /// <param name="allowedCountries">Comma separated list or null, Example: "US,FR" </param>
        /// <param name="deniedCountries">Comma separated list of countries you want to block or null, Example: "US,FR" </param>
        /// <param name="allowedReferrers">Comma separated list of allowed referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="deniedReferrers">Comma separated list of denied referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="allowedProtocol">Only allows requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="deniedProtocol">Denies requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="allowedUrls">allows you to tailor tokens to a particular asset or path. It restricts access to requests whose URL start with a specific relative path. You can input multiple paths separating each path with a comma. URLs are case-sensitive. Depending on the requirement, you can set up different value to provide different level of access</param>
        /// <returns></returns>
        public string EncryptV3(string key,
        DateTime expirationTime,
        string clientIPAddress = null,
        string allowedCountries = null,
        string deniedCountries = null,
        string allowedReferrers = null,
        string deniedReferrers = null,
        string allowedProtocol = null,
        string deniedProtocol = null,
        string allowedUrls = null)
        {
            StringBuilder token = new StringBuilder();
            /// ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com"
            /// php -d extension=.libs/ectoken.so example.php
            /// php -d extension=.libs/ectoken.so -r '$token = ectoken_encrypt_token("12345678", "ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com"); echo $token;'
            TimeSpan t = expirationTime - new DateTime(1970, 1, 1);
            int epoch = (int)t.TotalSeconds;
            token.Append($"ec_expire={epoch}");
            if (!string.IsNullOrEmpty(clientIPAddress)) token.Append($"&ec_clientip={clientIPAddress}");
            if (!string.IsNullOrEmpty(allowedCountries)) token.Append($"&ec_country_allow={allowedCountries}");
            if (!string.IsNullOrEmpty(deniedCountries)) token.Append($"&ec-country-deny={deniedCountries}");
            if (!string.IsNullOrEmpty(allowedReferrers)) token.Append($"&ec-ref-allow={allowedReferrers}");
            if (!string.IsNullOrEmpty(deniedReferrers)) token.Append($"&ec-ref-deny={deniedReferrers}");
            if (!string.IsNullOrEmpty(allowedProtocol)) token.Append($"&ec-proto-allow={allowedProtocol}");
            if (!string.IsNullOrEmpty(deniedProtocol)) token.Append($"&ec-proto-deny={deniedProtocol}");
            if (!string.IsNullOrEmpty(allowedUrls)) token.Append($"&ec-url-allow={allowedUrls}");
            return EncryptV3(key, token.ToString(), false);
        }

        #region Encrypt V3-AESGCM
        public string EncryptV3(String strKey, String strToken, bool blnVerbose)
        {
            if (strToken.Length > 512)
                throw new ArgumentException("Token exceeds maximum of 512 characters.");

            // make sure the user didn't pass in ec_secure=1
            // older versions of ecencrypt required users to pass this in
            // current users should not pass in ec_secure
            strToken = strToken.Replace("ec_secure=1&", "");
            strToken = strToken.Replace("ec_secure=1", "");

            // if verbose is turned on, show what is about to be encrypted
            if (blnVerbose)
                Debug.WriteLine("Token before encryption :  " + strToken);

            //key to SHA256
            SHA256 sha256 = SHA256.Create();
            byte[] arrKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(strKey));
            string encrypted = AESGCMEncrypt(strToken, arrKey, blnVerbose);
            return encrypted;
        }

        public string DecryptV3(String strKey, String strToken, bool blnVerbose)
        {
            if (blnVerbose)
                Debug.WriteLine("Token before decryption :  " + strToken);

            //key to SHA256
            SHA256 sha256 = SHA256.Create();
            byte[] arrKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(strKey));
            string decrypted = AESGCMDecrypt(strToken, arrKey, blnVerbose);
            if (blnVerbose)
                Debug.WriteLine("Token after decryption :  " + decrypted);
            return decrypted;
        }

        /// <summary>
        /// Encryption And Authentication (AES-GCM) of a UTF8 string.
        /// </summary>
        /// <param name="strToken">Token to Encrypt.</param>
        /// <param name="key">The key.</param>        
        /// <returns>
        /// Encrypted Message
        /// </returns>
        /// <exception cref="System.ArgumentException">StrToken Required!</exception>
        /// <remarks>
        /// Adds overhead of (Optional-Payload + BlockSize(16) + Message +  HMac-Tag(16)) * 1.33 Base64
        /// </remarks>
        private string AESGCMEncrypt(string strToken, byte[] key, bool blnVerbose)
        {
            if (string.IsNullOrEmpty(strToken))
                throw new ArgumentException("Secret Message Required!", "secretMessage");

            byte[] plainText = Encoding.UTF8.GetBytes(strToken);
            byte[] cipherText = null;
            cipherText = AESGCMEncrypt(plainText, key, blnVerbose);

            return base64urlencode(cipherText);
        }

        /// <summary>
        /// Encryption And Authentication (AES-GCM) of a UTF8 string.
        /// </summary>
        /// <param name="strToken">Token to Encrypt.</param>
        /// <param name="key">The key.</param>         
        /// <returns>Encrypted Message</returns>
        /// <remarks>
        /// Adds overhead of (Optional-Payload + BlockSize(16) + Message +  HMac-Tag(16)) * 1.33 Base64
        /// </remarks>
        private byte[] AESGCMEncrypt(byte[] strToken, byte[] key, bool blnVerbose)
        {
            //User Error Checks
            if (key == null || key.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "key");

            //Using random nonce large enough not to repeat
            byte[] iv = new byte[NonceBitSize / 8];
            Random.NextBytes(iv, 0, iv.Length);
            var cipher = new GcmBlockCipher(new AesFastEngine());
            // var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, nonSecretPayload);
            KeyParameter keyParam = new KeyParameter(key);
            ICipherParameters parameters = new ParametersWithIV(keyParam, iv);
            cipher.Init(true, parameters);
            //Generate Cipher Text With Auth Tag           
            var cipherText = new byte[cipher.GetOutputSize(strToken.Length)];
            var len = cipher.ProcessBytes(strToken, 0, strToken.Length, cipherText, 0);
            int len2 = cipher.DoFinal(cipherText, len);
            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Nonce
                    binaryWriter.Write(iv);
                    //Write Cipher Text
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        /// <summary>
        /// Decryption & Authentication (AES-GCM) of a UTF8 Message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="key">The key.</param>        
        /// <returns>Decrypted Message</returns>
        private string AESGCMDecrypt(string encryptedMessage, byte[] key, bool blnVerbose)
        {
            if (string.IsNullOrEmpty(encryptedMessage))
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            var cipherText = base64urldecode(encryptedMessage);
            byte[] plaintext = null;
            plaintext = AESGCMDecrypt(cipherText, key, blnVerbose);
            return plaintext == null ? null : Encoding.UTF8.GetString(plaintext);
        }

        /// <summary>
        /// Decryption & Authentication (AES-GCM) of a UTF8 Message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="key">The key.</param>
        /// <param name="nonSecretPayloadLength">Length of the optional non-secret payload.</param>
        /// <returns>Decrypted Message</returns>
        private byte[] AESGCMDecrypt(byte[] encryptedMessage, byte[] key, bool blnVerbose)
        {
            //User Error Checks
            if (key == null || key.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "key");

            if (encryptedMessage == null || encryptedMessage.Length == 0)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            using (var cipherStream = new MemoryStream(encryptedMessage))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                //Grab Nonce
                var iv = cipherReader.ReadBytes(NonceBitSize / 8);

                var cipher = new GcmBlockCipher(new AesFastEngine());
                KeyParameter keyParam = new KeyParameter(key);
                ICipherParameters parameters = new ParametersWithIV(keyParam, iv);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - iv.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);
                }
                catch (InvalidCipherTextException)
                {
                    return null;
                }
                return plainText;
            }
        }

        private string base64urlencode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding                      
            return s;
        }

        private byte[] base64urldecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new System.Exception(
             "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }
        #endregion
    }
}
