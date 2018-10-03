<?php

namespace ECToken3;

interface Encodable {

  /**
   * Create encoded representation of the data structure
   * 
   * @return string
   */
  public function encode();

  /**
   * Decode input data into the data structure. Not static because the data
   * structure may have internal validation logic that may affect decoding.
   * 
   * @param string $data data to decode
   * @throws Exception upon error
   */
  public function decode($data);
}