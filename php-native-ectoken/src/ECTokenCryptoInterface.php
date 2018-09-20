<?php

namespace ECToken3;

interface ECTokenCryptoInterface {

  public function encrypt($input);
  public function decrypt($input);
}