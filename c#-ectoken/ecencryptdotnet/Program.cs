/*
 * EdgeCast Token Encryption/Decryption Application for .Net Framework
 * 
EdgeCast Token Authentication
Copyright (C) 2010 EdgeCast Networks, Inc.  All rights reserved.

Use of source and binary forms, with or without modification is permitted provided
that there is written consent by EdgeCast Networks, Inc. Redistribution in source and binary  
forms  is not permitted.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. * 
 * 
 * */

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ec_encrypt
{
    class Program
    {
        private static readonly SecureRandom Random = new SecureRandom();
        private static readonly Random _rand = new Random((int)DateTime.Now.Ticks);
        private static readonly int MIN_RANDOM_LENGTH = 4;
        private static readonly int MAX_RANDOM_LENGTH = 8;
        
        private static readonly string DECRYPT_COMMAND = "decrypt";                
        private static readonly string VERBOSE_COMMAND = "-v";        

        static readonly char[] PADDING = { '=' };

        //Preconfigured Encryption Parameters
        public static readonly int NonceBitSize = 96;
        public static readonly int MacBitSize = 128;
        public static readonly int KeyBitSize = 256;

        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 1)
                {

                    System.Console.WriteLine("EC Token encryption and decryption utility.  Version: 3.0.0");
                    Environment.Exit(0);
                }
                
                if (args.Length < 2)
                {
                    // display some examples of how to use this application
                    System.Console.WriteLine("----------------------------------------------------------------");
                    System.Console.WriteLine("| Usage / Help:");                    
                    System.Console.WriteLine("|       ectoken3.exe <key> <text>             | create v3 encrypt token using <text> and <key>");
                    System.Console.WriteLine("|       ectoken3.exe <key> <text> -v          | create v3 encrypt token using <text> and <key> in verbose mode");                 
                    System.Console.WriteLine("|       ectoken3.exe decrypt <key> <text>     | decrypt token");
                    System.Console.WriteLine("|       ectoken3.exe decrypt <key> <text> -v  | decrypt token in verbose mode");
                    System.Console.WriteLine("---------------------------------------------------------------");
                    Environment.Exit(1);
                }

                // variables to store the key and token
                string strKey = "";
                string strToken = "";
                string strResult = "";                
                bool isEncrypt = true;
                
                // we can turn on verbose output to help debug problems
                bool blnVerbose = false;

                if (blnVerbose) System.Console.WriteLine("----------------------------------------------------------------\n");

                if (args.Length > 2){ if(args[2] == VERBOSE_COMMAND)  blnVerbose = true;}
                if (args.Length > 3) { if (args[3] == VERBOSE_COMMAND) blnVerbose = true; }

                if (args[0] == DECRYPT_COMMAND) isEncrypt = false;                               

                // if this is a decrypt function, then take an encrypted token and decrypt it
                if (isEncrypt)
                {
                    strKey = args[0];
                    strToken = args[1];             

                    try
                    {                    
                        strResult = EncryptV3(strKey, strToken, blnVerbose);

                        if (string.IsNullOrEmpty(strResult))
                            System.Console.WriteLine("Failed to encrypt token");
                    }
                    catch (System.Exception ex)
                    {
                        if (blnVerbose)
                        {
                            System.Console.WriteLine("Exception occured while encrypting token" + ex.Message);
                            Environment.Exit(1);
                        }
                    }
                }
                else
                {
                    strKey = args[1];
                    strToken = args[2];

                    try
                    {
                        strResult = DecryptV3(strKey, strToken, blnVerbose);
                        if (string.IsNullOrEmpty(strResult))
                        {
                            System.Console.WriteLine("Failed to decrypt token.");
                        }
                    }
                    catch (System.Exception ex)
                    {
                        if (blnVerbose)
                            System.Console.WriteLine("Exception occured while encrypting token" + ex.Message);                        
                    }
                }

                if (blnVerbose)
                {
                    System.Console.WriteLine("----------------------------------------------------------------");                 
                }

                if (!string.IsNullOrEmpty(strResult))
                {
                    System.Console.WriteLine(strResult);
                }
                else
                {
                    System.Console.WriteLine("Failed to encrypt/decrypt token");
                    Environment.Exit(1);
                }
            }
            catch (System.Exception ex)
            {
                System.Console.WriteLine("Exception occured while encrypting/decrypting token" + ex.Message);
            }
        }

        public static string NextRandomString(int length){
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[length];

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[_rand.Next(chars.Length)];
            }

            string randomString = new String(stringChars);
            return randomString;
        }

        public static string NextRandomString(){
            int length = _rand.Next(MIN_RANDOM_LENGTH, MAX_RANDOM_LENGTH);
            return NextRandomString(length);
        }

        #region Encrypt V3-AESGCM
        public static string EncryptV3(String strKey, String strToken, bool blnVerbose)
        {
            if (strToken.Length > 512)
            {
                System.Console.WriteLine("Exceeds maximum of 512 characters.");
                Environment.Exit(1);
            }            
            // make sure the user didn't pass in ec_secure=1
            // older versions of ecencrypt required users to pass this in
            // current users should not pass in ec_secure
            strToken = strToken.Replace("ec_secure=1&", "");
            strToken = strToken.Replace("ec_secure=1", "");

            // if verbose is turned on, show what is about to be encrypted
            if (blnVerbose)            
                System.Console.WriteLine("Token before encryption :  " + strToken);            

            //key to SHA256
            SHA256 sha256 = SHA256Managed.Create();
            byte[] arrKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(strKey));
            string encrypted = AESGCMEncrypt(strToken, arrKey,blnVerbose);     
            return encrypted;
        }

        public static string DecryptV3(String strKey, String strToken, bool blnVerbose)
        {          
            if (blnVerbose)            
                System.Console.WriteLine("Token before decryption :  " + strToken);           

            //key to SHA256
            SHA256 sha256 = SHA256Managed.Create();
            byte[] arrKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(strKey));            
            string decrypted = AESGCMDecrypt(strToken, arrKey,blnVerbose);
            if (blnVerbose)            
                System.Console.WriteLine("Token after decryption :  " + decrypted);            
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
        public static string AESGCMEncrypt(string strToken, byte[] key, bool blnVerbose)
        {
            if (string.IsNullOrEmpty(strToken))
                throw new ArgumentException("Secret Message Required!", "secretMessage");

            byte[] plainText = Encoding.UTF8.GetBytes(strToken);
            byte[] cipherText = AESGCMEncrypt(plainText, key,blnVerbose);

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
        public static byte[] AESGCMEncrypt(byte[] strToken, byte[] key,bool blnVerbose)
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
        public static string AESGCMDecrypt(string encryptedMessage, byte[] key, bool blnVerbose)
        {
            if (string.IsNullOrEmpty(encryptedMessage))
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            var cipherText = base64urldecode(encryptedMessage);
            var plaintext = AESGCMDecrypt(cipherText, key,blnVerbose);
            return plaintext == null ? null : Encoding.UTF8.GetString(plaintext);
        }

        /// <summary>
        /// Decryption & Authentication (AES-GCM) of a UTF8 Message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="key">The key.</param>
        /// <param name="nonSecretPayloadLength">Length of the optional non-secret payload.</param>
        /// <returns>Decrypted Message</returns>
        public static byte[] AESGCMDecrypt(byte[] encryptedMessage, byte[] key, bool blnVerbose)
        {
            //User Error Checks
            if (key == null || key.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "key");

            if (encryptedMessage == null || encryptedMessage.Length == 0)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            using (var cipherStream = new MemoryStream(encryptedMessage))
            using (var cipherReader = new BinaryReader(cipherStream)){
                //Grab Nonce
                var iv = cipherReader.ReadBytes(NonceBitSize / 8);

                var cipher = new GcmBlockCipher(new AesFastEngine());
                KeyParameter keyParam = new KeyParameter(key);
                ICipherParameters parameters = new ParametersWithIV(keyParam, iv);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length  - iv.Length);
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

        static string base64urlencode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding                      
            return s;
        }

        static byte[] base64urldecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new System.Exception(
                  "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }
        #endregion
    }
}
