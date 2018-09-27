<?php

namespace ECToken3;

use Respect\Validation\Validator as v;

class ECTokenParameterFactory implements ParameterFactory {

  private $def;

  public function __construct() {
    v::with('ECToken3\\Rules');
    
    $this->def = [
      'ec_clientip' => [
        'validator' => v::scalarVal()->ip(),
        'maxSize' => 1,
      ],
      'ec_country_allow' => [
        'validator' => v::scalarVal()->ECCountryCode(),
        'maxSize' => INF,
      ],
      'ec_country_deny' => [
        'validator' => v::scalarVal()->ECCountryCode(),
        'maxSize' => INF,
      ],
      'ec_expire' => [
        'validator' => v::scalarVal()->intVal(),
        'maxSize' => 1
      ],
      'ec_host_allow' => [
        'validator' => v::scalarVal()->alnum('. - *')->noWhitespace(),
        'maxSize' => INF
      ],
      'ec_host_deny' => [
        'validator' => v::scalarVal()->alnum('. - *')->noWhitespace(),
        'maxSize' => INF
      ],
      'ec_proto_allow' => [
        'validator' => v::scalarVal()->in(['http', 'https']),
        'maxSize' => 1,
      ],
      'ec_proto_deny' => [
        'validator' => v::scalarVal()->in(['http', 'https']),
        'maxSize' => 1,
      ],
      'ec_ref_allow' => [
        'validator' => v::scalarVal()->notBlank(),
        'maxSize' => INF,
      ],
      'ec_ref_deny' => [
        'validator' => v::scalarVal()->notBlank(),
        'maxSize' => INF,
      ],
      'ec_url_allow' => [
        'validator' => v::scalarVal()->notBlank(),
        'maxSize' => INF,
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildParameter($name) {
    if (!isset($this->def[$name])) {
      throw new \LogicException("Unable to create Parameter. Unknown parameter name ($name)");
    }

    return new ValidatingParameter($name, $this->def[$name]['validator'], $this->def[$name]['maxSize']);
  }

  /**
   * {@inheritdoc}
   */
  public function getParameterNames() {
    return array_keys($this->def);
  }

  /**
   * {@inheritdoc}
   */
  public function isInstance(Parameter $p) {
    try {
      $model = $this->buildParameter($p->getName());
    } catch (\LogicException $e) {
      return false;
    }

    if (get_class($p) != get_class($model)) {
      return false;
    }

    return true;
  }
}