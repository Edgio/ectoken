<?php

namespace ECToken3;

use Respect\Validation\Validator as v;

class ValidatingParameter implements Parameter {

  private $name;
  private $validator;
  private $maxSize;
  private $values = array();

  /**
   * @param string $name
   * @param Respect\Validation\Validator $validator
   * @param int $maxSize
   */
  public function __construct($name, v $validator, $maxSize = INF) {
    $this->name = $name;
    $this->validator = $validator;
    $this->maxSize = $maxSize;
  }

  /**
   * {@inheritdoc}
   */
  public function getName() {
    return $this->name;
  }

  /**
   * {@inheritdoc}
   */
  public function getMaxSize() {
    return $this->maxSize;
  }

  /**
   * {@inheritdoc}
   */
  public function getValues() {
    return $this->values;
  }

  /**
   * {@inheritdoc}
   */
  public function setValues($values) {
    if (!is_array($values) && !$values instanceof \Traversable) {
      throw new \IllegalArgumentException(__METHOD__ . ' expects array or Traversable object');
    }

    // Get the values into an array with numerical indexes
    $values = is_array($values) ? array_values($values) : iterator_to_array($values, false);

    if (count($values) > $this->maxSize) {
      throw new \IllegalArgumentException("Number of values exceeds maximum ({$this->maxSize})");
    }

    foreach ($values as $value) {
      $this->validator->assert($value);
    }

    // By now this will be ok or fail with thrown Exception
    $this->values = $values;
  }

  /**
   * {@inheritdoc}
   */
  public function addValue($value) {
    $this->offsetSet(null, $value);
  }

  /**
   * {@inheritdoc}
   */
  public function offsetExists($index) {
    return isset($this->values[$index]);
  }

  /**
   * {@inheritdoc}
   */
  public function offsetGet($index) {
    return isset($this->values[$index]) ? $this->values[$index] : null;
  }

  /**
   * {@inheritdoc}
   */
  public function offsetSet($index, $value) {
    // If index is null, append
    if (empty($index)) {
      $index = $this->count();
    }

    if (!isset($this->values[$index]) && count($this->values) >= $this->maxSize) {
      throw new \LogicError("Parameter cannot contain more than {$this->maxSize} values");
    }

    $this->validator->assert($value);

    $this->values[$index] = $value;
  }

  /**
   * {@inheritdoc}
   */
  public function offsetUnset($index) {
    unset($this->values[$index]);
  }

  /**
   * {@inheritdoc}
   */
  public function count() {
    return count($this->values);
  }
}