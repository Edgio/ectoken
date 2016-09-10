/**
 * EdgeCast Token Encryption/Decryption Application v3.0 for Java
 *
 * EdgeCast Token Authentication
 * Copyright (C) 2012 EdgeCast Networks, Inc.  All rights reserved.

 * Use of source and binary forms, with or without modification is permitted provided
 * that there is written consent by EdgeCast Networks, Inc. Redistribution in
 * source and binary forms is not permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **/
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Arrays;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import org.apache.commons.codec.binary.Base64;

public class ECToken3 {
    private final static Random RANDOM = new Random(
                                                    System.currentTimeMillis());
    private final static int UPPERBOUND = 8;
    private final static int LOWERBOUND = 4;
    static final int MAC_SIZE_BITS = 128;
    private final static String ALPHANUMERIC = "-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxzy";

    //: --------------------------------------------------------------------
    //: bytes to hex
    //: --------------------------------------------------------------------
    final protected static char[] hexArray = "0123456789abcdef".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    //: --------------------------------------------------------------------
    //: encrypt v3
    //: --------------------------------------------------------------------
    public static final String encryptv3(String key, String input)
        throws java.io.UnsupportedEncodingException,
               java.security.NoSuchAlgorithmException,
               javax.crypto.NoSuchPaddingException,
               java.security.InvalidKeyException,
               javax.crypto.IllegalBlockSizeException,
               javax.crypto.BadPaddingException,
               java.security.InvalidAlgorithmParameterException {

        //System.out.format("+-------------------------------------------------------------\n");
        //System.out.format("| Encrypt\n");
        //System.out.format("+-------------------------------------------------------------\n");
        //System.out.format("| key:                   %s\n", key);
        //System.out.format("| token:                 %s\n", input);

        //----------------------------------------------------
        // Get SHA-256 of key
        //----------------------------------------------------
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes("ASCII"));
        byte[] keyDigest = md.digest();

        //----------------------------------------------------
        // Get Random IV
        //----------------------------------------------------
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[12];
        random.nextBytes(ivBytes);

        //----------------------------------------------------
        // Encrypt
        //----------------------------------------------------
        AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(true, new AEADParameters(new KeyParameter(keyDigest), MAC_SIZE_BITS, ivBytes));
        byte[] inputBytes = input.getBytes("ASCII");

        byte[] enc = new byte[cipher.getOutputSize(inputBytes.length)];

        try {
            int res = cipher.processBytes(inputBytes,
                                          0,
                                          inputBytes.length,
                                          enc,
                                          0);
            cipher.doFinal(enc, res);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        byte[] ivPlusCipherText = new byte[ivBytes.length + enc.length];
        System.arraycopy(ivBytes,0,ivPlusCipherText, 0,              ivBytes.length);
        System.arraycopy(enc,    0,ivPlusCipherText, ivBytes.length, enc.length);

        //System.out.format("+-------------------------------------------------------------\n");
        //System.out.format("| iv:                    %s\n", bytesToHex(ivBytes));
        //System.out.format("| ciphertext:            %s\n", bytesToHex(Arrays.copyOfRange(enc, 0, enc.length - 16)));
        //System.out.format("| tag:                   %s\n", bytesToHex(Arrays.copyOfRange(enc, enc.length - 16, enc.length)));
        //System.out.format("+-------------------------------------------------------------\n");
        //System.out.format("| token:                 %s\n", bytesToHex(ivPlusCipherText));
        //System.out.format("+-------------------------------------------------------------\n");

        String result = null;
        byte[] temp = null;
        Base64 encoder = new Base64(0, temp, true);
        byte[] encodedBytes = encoder.encode(ivPlusCipherText);
        String encodedStr = new String(encodedBytes, "ASCII").trim();
        String encodedStrTrim = encodedStr.trim();
        return encodedStr.trim();
    }

    //: --------------------------------------------------------------------
    //: decrypt v3
    //: --------------------------------------------------------------------
    public static final String decryptv3(String key, String input)
        throws java.io.UnsupportedEncodingException,
               java.security.NoSuchAlgorithmException,
               javax.crypto.NoSuchPaddingException,
               java.security.InvalidKeyException,
               javax.crypto.IllegalBlockSizeException,
               javax.crypto.BadPaddingException,
               java.security.InvalidAlgorithmParameterException {

        //----------------------------------------------------
        // Base64 decode
        //----------------------------------------------------
        String result = null;
        Base64 encoder = new Base64(true);
        byte[] inputBytes = encoder.decode(input.getBytes("ASCII"));

        //----------------------------------------------------
        // Get SHA-256 of key
        //----------------------------------------------------
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes("ASCII"));
        byte[] keyDigest = md.digest();

        //System.out.format("+-------------------------------------------------------------\n");
        //System.out.format("| Decrypt\n");
        //System.out.format("+-------------------------------------------------------------\n");
        //System.out.format("| key:                   %s\n", key);
        //System.out.format("| token:                 %s\n", input);

        //----------------------------------------------------
        // Rip up the ciphertext
        //----------------------------------------------------
        byte[] ivBytes = new byte[12];
        ivBytes = Arrays.copyOfRange(inputBytes, 0, ivBytes.length);

        byte[] cipherBytes = new byte[inputBytes.length - ivBytes.length];
        cipherBytes = Arrays.copyOfRange(inputBytes, ivBytes.length, inputBytes.length);

        //----------------------------------------------------
        // Decrypt
        //----------------------------------------------------
        AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(keyDigest), MAC_SIZE_BITS, ivBytes));

        //System.out.format("+-------------------------------------------------------------\n");
        //System.out.format("| iv:                    %s\n", bytesToHex(ivBytes));
        //System.out.format("| ciphertext:            %s\n", bytesToHex(Arrays.copyOfRange(cipherBytes, 0, cipherBytes.length - 16)));
        //System.out.format("| tag:                   %s\n", bytesToHex(Arrays.copyOfRange(cipherBytes, cipherBytes.length - 16, cipherBytes.length)));
        //System.out.format("+-------------------------------------------------------------\n");

        byte[] dec = new byte[cipher.getOutputSize(cipherBytes.length)];

        try {
            int res = cipher.processBytes(cipherBytes,
                                          0,
                                          cipherBytes.length,
                                          dec,
                                          0);
            cipher.doFinal(dec, res);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //System.out.format("token: %s\n", new String(dec, "ASCII"));
        return new String(dec, "ASCII");
    }

    public static final void usage() {

        System.out.println("Usage: ECToken3 encrypt <key> <text>");
        System.out.println("       ECToken3 decrypt <key> <text>");
        System.out.println("");
        System.out.println("Version 2 compatibility:");
        System.out.println("  use -2 to specify version 2 tokens eg:");
        System.out.println("       ECToken3 -2 encrypt <key> <text>");
        System.out.println("       ECToken3 -2 decrypt <key> <text>");
        System.exit(1);
    }

    //: --------------------------------------------------------------------
    //: main
    //: --------------------------------------------------------------------
    public static final void main(String[] args) throws Exception {

        if (args.length == 1 &&
            args[0].equals("--version")){
            System.out.println("EC Token encryption and decryption utility.  Version: 3.0.0\n");
            System.exit(0);
        }

        int arg_offset = 0;
        if (args.length != 3) {
            usage();
        }

        String action = args[arg_offset+0];
        String key = args[arg_offset+1];
        String input = args[arg_offset+2];
        String outString = "";
        if (action.equals("encrypt")) {
            outString = ECToken3.encryptv3(key, input);
        } else if (action.equals("decrypt")) {
            outString = ECToken3.decryptv3(key, input);
        }
        System.out.println(outString);
    }
}
