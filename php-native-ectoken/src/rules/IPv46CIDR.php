<?php

namespace ECToken3\Rules;

use Respect\Validation\Validator as v;
use Respect\Validation\Rules\AbstractRule;

/**
 * Validate that input is a valid IPv4 or IPv6 address with or without CIDR
 */
class IPv46CIDR extends AbstractRule {
  public function validate($input) {
    $cidr = null;

    if (strpos($input, '/') !== false) {
      list($input, $cidr) = explode('/', $input, 2);
    }

    if (v::ip(FILTER_FLAG_IPV4)->validate($input)) {
      return v::oneOf(
        v::nullType(),
        v::intVal()->between(1, 24)
      )->validate($cidr);
    } 
    elseif (v::ip(FILTER_FLAG_IPV6)->validate($input)) {
      return v::oneOf(
        v::nullType(),
        v::intVal()->between(1, 128)
      )->validate($cidr);
    }

    // Not a valid IP? Fail!
    return false;
  }
}