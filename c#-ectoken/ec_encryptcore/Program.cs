using System;
using ecencryptstdlib;

namespace ec_encryptcore
{
    class Program
    {
        private static readonly string DECRYPT_COMMAND = "decrypt";
        private static readonly string VERBOSE_COMMAND = "-v";

        static void Main(string[] args)
        {
            try
            {
                ECTokenGenerator tokenGenerator = new ECTokenGenerator();

                if (args.Length == 1)
                {

                    System.Console.WriteLine("EC Token encryption and decryption utility.  Version: 3.0.0");
                    System.Console.WriteLine(".NET Core Version supported by ecencryptstdlib (.NET Standard 1.4) ");
                    Environment.Exit(0);
                }

                if (args.Length < 2)
                {
                    // display some examples of how to use this application
                    System.Console.WriteLine("----------------------------------------------------------------");
                    System.Console.WriteLine("| Usage / Help:");
                    System.Console.WriteLine("|       ec_encryptcore.exe <key> <text>             | create v3 encrypt token using <text> and <key>");
                    System.Console.WriteLine("|       ec_encryptcore.exe <key> <text> -v          | create v3 encrypt token using <text> and <key> in verbose mode");
                    System.Console.WriteLine("|       ec_encryptcore.exe decrypt <key> <text>     | decrypt token");
                    System.Console.WriteLine("|       ec_encryptcore.exe decrypt <key> <text> -v  | decrypt token in verbose mode");
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

                if (args.Length > 2) { if (args[2] == VERBOSE_COMMAND) blnVerbose = true; }
                if (args.Length > 3) { if (args[3] == VERBOSE_COMMAND) blnVerbose = true; }

                if (args[0] == DECRYPT_COMMAND) isEncrypt = false;

                // if this is a decrypt function, then take an encrypted token and decrypt it
                if (isEncrypt)
                {
                    strKey = args[0];
                    strToken = args[1];

                    try
                    {
                        strResult = tokenGenerator.EncryptV3(strKey, strToken, blnVerbose);

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
                        strResult = tokenGenerator.DecryptV3(strKey, strToken, blnVerbose);
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
    }
}