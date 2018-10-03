<?php

namespace ECToken3;

interface CryptoInterface {

  public function encrypt($input);
  public function decrypt($input);
}