<?php

namespace ECToken3;

use Respect\Validation\Validator as v;

class ConfigurableToken implements Token, Encodable {

  const PARAMETER_SEPARATOR = '&';
  const NAME_VALUE_SEPARATOR = '=';
  const VALUE_SEPARATOR = ',';

  private $pfactory;
  private $parameters = array();

  public function __construct(ParameterFactory $pfactory) {
    $this->pfactory = $pfactory;
  }

  public function getParameterFactory() {
    return $this->pfactory;
  }

  /**
   * Convinience method that adds a value to a named parameter, creating or
   * adding to the parameter as needed
   * 
   * @param string $name Parameter name to store the value in
   * @param mixed $value
   */
  public function addValue($name, $value) {
    if ($this->offsetExists($name)) {
      $this->offsetGet($name)->addValue($value);
    } else {
      $p = $this->pfactory->buildParameter($name);
      $p->addValue($value);
      $this->setParameter($p);
    }

    return $this;
  }

  /**
   * {@inheritdoc}
   */
  public function setParameter(Parameter $p) {
    $this->offsetSet($p->getName(), $p);
  }

  /**
   * {@inheritdoc}
   */
  public function getParameters() {
    return $this->parameters;
  }

  /**
   * {@inheritdoc}
   */
  public function offsetExists($index) {
    return isset($this->parameters[$index]);
  }

  /**
   * {@inheritdoc}
   */
  public function offsetSet($index, $value) {
    if (!($value instanceof Parameter)) {
      throw new \InvalidArgumentException(__METHOD__ . ' expects parameter 2 to be an instance of ECToken\\Parameter');
    }

    if ($index != $value->getName()) {
      throw new \InvalidArgumentException('Input keys must match Parameter names');
    }

    if (!$this->pfactory->isInstance($value)) {
      throw new \InvalidArgumentException('Unknown Paramter configuration');
    }

    $this->parameters[$index] = $value;
  }

  /**
   * {@inheritdoc}
   */
  public function offsetGet($index) {
    return isset($this->parameters[$index]) ? $this->parameters[$index] : null;
  }

  /**
   * {@inheritdoc}
   */
  public function offsetUnset($index) {
    unset($this->parameters[$index]);
  }

  /**
   * {@inheritdoc}
   */
  public function count() {
    return count($this->parameters);
  }

  /**
   * {@inheritdoc}
   */
  public function encode() {
    $sorted = $this->getParameters();
    ksort($sorted);
    return array_reduce($sorted, [$this, 'encodeReduceParameter']);
  }

  /**
   * Callback for use in array_reduce to encode Parameters
   */
  private function encodeReduceParameter($carry, Parameter $p) {
    // Require parameters to have values; empty values are pointless
    if ($p->count() == 0) { return; }

    // if $carry is empty, this is the first parameter
    $result = empty($carry) ? '' : $carry . self::PARAMETER_SEPARATOR;

    $result .= $p->getName() . self::NAME_VALUE_SEPARATOR;
    $result .= array_reduce($p->getValues(), [$this, 'encodeReduceParameterValue']);

    return $result;
  }

  /**
   * Callback for use in array_reduce to encode Parameter values
   */
  private function encodeReduceParameterValue($carry, $value) {
    // if $carry is empty, this is the first value
    $result = empty($carry) ? '' : $carry . self::VALUE_SEPARATOR;

    /**
     * Percent encode values for serialization. Candidates for encoding include
     * all URL unsafe characters per RFC 3986 plus ampersand (&), equals (=), 
     * and comma (,), which are all reserved characters in the ectoken 
     * serialization format (see VDMS Token-Based Authentication Administration 
     * Guide)
     */
    $result .= preg_replace_callback(
      '/[^A-Za-z0-9,._~!$\'()*+;:@\/\-]/u',
      function($matches) { 
        // Correctly percent encodes multi-byte characters
        return '%' . implode('', array_map('dechex', array_map('ord', str_split($matches[0])))); 
      },
      $value
    );

    return $result;
  }

  /**
   * {@inheritdoc}
   */
  public function decode($data) {
    $pdata = explode(self::PARAMETER_SEPARATOR, $data);

    foreach ($pdata as $pdatum) {
      list($name, $value) = explode(self::NAME_VALUE_SEPARATOR, $pdatum, 2);

      $parameter = $this->pfactory->buildParameter($name);

      $values = $parameter->getMaxSize() > 1
        ? explode(self::VALUE_SEPARATOR, $value)
        : [$value];

      $parameter->setValues($values);

      $this->setParameter($parameter);
    }
  }
}