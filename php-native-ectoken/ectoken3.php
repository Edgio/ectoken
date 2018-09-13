<?php

namespace ECToken3;

use \AESGCM\AESGCM;
use \ParagonIE\ConstantTime\RFC4648;

require __DIR__ . '/vendor/autoload.php';

abstract class ECToken3 {

  protected const IV_SIZE_BYTES = 12;
  protected const TAG_SIZE_BITS = 128; // 16 bytes

  public function encrypt($key, $input) {
    // Get sha-256 hash of key as bytes
    $key_digest = hash('sha256', $key, true);

    // Generate initialization vector
    $iv = random_bytes(self::IV_SIZE_BYTES);

    // Encrypt input with tag appended
    $ciphertext = AESGCM::encryptAndAppendTag($key_digest, $iv, $input, null, self::TAG_SIZE_BITS);

    // Prepend initialization vector
    $result_bits = $iv . $ciphertext;

    // Encode as a URL-safe base64 string, trim padding, and return
    return self::base64UrlSafeEncode($result_bits);
  }

  public function decrypt($key, $input) {
    // Get sha-256 hash of key as bytes
    $key_digest = hash('sha256', $key, true);

    // Decode URL-safe base64 encoded input
    $input_bits = self::base64UrlSafeDecode($input);

    // Extract initialization vector
    $iv = mb_substr($input_bits, 0, self::IV_SIZE_BYTES, '8bit');

    // The remainder is cyphertext + tzg
    $ciphertext = mb_substr($input_bits, self::IV_SIZE_BYTES, null, '8bit');

    // Decrypt ciphertext and return
    return AESGCM::decryptWithAppendedTag($key_digest, $iv, $ciphertext, null, self::TAG_SIZE_BITS);
  }

  /**
   * URL-safe base64 encoding with padding characters removed
   */
  private function base64UrlSafeEncode($input) {
    return rtrim(RFC4648::base64UrlSafeEncode($input), '=');
  }

  /**
   * We don't need to restore padding because our decoder doesn't require it.
   * This function exists for symmetry with self::base64UrlSafeEncode()
   */
  private function base64UrlSafeDecode($input) {
    return RFC4648::base64UrlSafeDecode($input);
  }
}