<?php

namespace ECToken3;

use \AESGCM\AESGCM;
use \ParagonIE\ConstantTime\RFC4648;

require __DIR__ . '/../vendor/autoload.php';

class Crypto implements CryptoInterface {

  const IV_SIZE_BYTES = 12;
  const TAG_SIZE_BITS = 128; // 16 bytes
  const TOKEN_MAX_LENGTH = 512;

  private $keyDigest;

  public function __construct($key) {
    $this->keyDigest = hash('sha256', $key, true);
  }

  public function encrypt($input) {
    // Check that generated token will not exceed max length.
    $result_bits_length = (self::TAG_SIZE_BITS / 8) + self::IV_SIZE_BYTES + strlen($input);
    
    // Note: base64 encoding the output inflates it by a factor of 1/3
    if ($result_bits_length > self::TOKEN_MAX_LENGTH * 0.75) {
      throw new \LengthException('Generated token exceeds maximumum length of ' . self::TOKEN_MAX_LENGTH . ' characters');
    }

    // Generate initialization vector
    $iv = random_bytes(self::IV_SIZE_BYTES);

    // Encrypt input with tag appended
    $ciphertext = AESGCM::encryptAndAppendTag($this->keyDigest, $iv, $input, null, self::TAG_SIZE_BITS);

    // Prepend initialization vector
    $result_bits = $iv . $ciphertext;

    // Encode as a URL-safe base64 string, trim padding, and return
    return rtrim(RFC4648::base64UrlSafeEncode($result_bits), '=');
  }

  public function decrypt($input) {
    // Decode URL-safe base64 encoded input
    $input_bits = RFC4648::base64UrlSafeDecode($input);

    // Extract initialization vector
    $iv = mb_substr($input_bits, 0, self::IV_SIZE_BYTES, '8bit');

    // The remainder is cyphertext + tzg
    $ciphertext = mb_substr($input_bits, self::IV_SIZE_BYTES, null, '8bit');

    // Decrypt ciphertext and return
    return AESGCM::decryptWithAppendedTag($this->keyDigest, $iv, $ciphertext, null, self::TAG_SIZE_BITS);
  }
}