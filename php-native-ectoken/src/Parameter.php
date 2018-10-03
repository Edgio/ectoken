<?php

namespace ECToken3;

interface Parameter extends \ArrayAccess, \Countable {

  /**
   * Get the name of this parameter
   * 
   * @return string
   */
  public function getName();

  /**
   * Get the maximum number of values this Parameter can hold
   * 
   * @return int
   */
  public function getMaxSize();

  /**
   * Get the values of this parameter
   * 
   * @return array
   */
  public function getValues();

  /**
   * Set the values of this parameter
   * 
   * @param array
   */
  public function setValues($values);

  /**
   * Add a value to this parameter
   */
  public function addValue($value);
}