<?php

namespace ECToken3;

/**
 * ParameterFactory centralizes the configuration of configurable Tokens and
 * the creation of Parameters based on that configuration.
 */
interface ParameterFactory {

  /**
   * Create a new Parameter by name;
   * 
   * @param string $name the name of the Parameter to generate
   * @throws LogicException if the name is unknown
   */
  public function buildParameter($name);

  /**
   * Return an array of parameter names this factory is able to create 
   * Parameters for
   * 
   * @return array
   */
  public function getParameterNames();

  /**
   * Determine if a Parameter could have been created by this factory
   * 
   * @param Parameter Parameter to check
   * @return boolean
   */
  public function isInstance(Parameter $p);
}