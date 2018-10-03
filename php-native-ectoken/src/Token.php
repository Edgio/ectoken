<?php

namespace ECToken3;

/**
 * A Token is a collection of uniquely named Parameters
 */
interface Token extends \ArrayAccess, \Countable {

  /**
   * Convinience method that adds a value to a named parameter, creating or
   * adding to the parameter as needed
   * 
   * @param string $name Parameter name to store the value in
   * @param mixed $value
   * @return Token return the token for chainability
   */
  public function addValue($name, $value);

  /**
   * Add a Parameter to the Token
   * 
   * @param ECToken3\Parameter $parameter
   */
  function setParameter(Parameter $parameter);

  /**
   * Return the Parameters as an array keyed by the Parameter name
   * 
   * @return array
   */
  function getParameters();
}