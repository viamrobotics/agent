Feature: Bluetooth provisioning
  Background:
    Given viam-agent is installed

  Scenario: Provision via bluetooth
    When viam-agent enters provisioning mode
    And a phone provisions the machine via bluetooth
    Then the device is online
