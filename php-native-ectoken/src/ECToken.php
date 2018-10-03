<?php

namespace ECToken3;

class ECToken extends ConfigurableToken {

  public function __construct() {
    parent::__construct(new ECTokenParameterFactory());
  }
}