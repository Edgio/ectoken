<?php

namespace ECToken3;

interface EncoderInterface {

  /**
   * Encode object to string
   */
  function encode(Encodable $object);

  /**
   * Decode input data
   * 
   * @param string $data
   * @param Encodable $into Encodable object into which decoded data will be placed
   * @return Encodable returns $into after decoding
   */
  function decode($data, Encodable $into);
}