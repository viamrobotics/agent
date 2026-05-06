@darwin
Feature: bluetooth provisioning
  Background:
    Given viam-agent is installed at the version under test
    And the viam-agent systemd unit is enabled
    And the viam-agent systemd unit is running with version under test
    And there are no available wifi networks
    And viam-agent cannot reach the app
  Scenario: The agent enters automatic provisioning mode when expected
    When the provisioning hotspot is not up
    Then the viam-agent bluetooth device becomes discoverable with the expected characteristics within 120 seconds
  Scenario: The agent can join an unknown insecure network when one is provided during bluetooth provisioning
    When viam-agent is in forced provisioning mode
    And the viam-agent bluetooth device is discoverable with the expected characteristics
    And the host shares an insecure wifi network via bluetooth
  Scenario: The agent can join an unknown secure network when one is provided during bluetooth provisioning
    When viam-agent is in forced provisioning mode
    And the viam-agent bluetooth device is discoverable with the expected characteristics
    And the host shares a secure wifi network via bluetooth
    Then viam-agent can reach the app
  Scenario: The agent can join a known secure network when one is provided during bluetooth provisioning
    When viam-agent is connected to a network
    When viam-agent is in forced provisioning mode
    And the viam-agent bluetooth device is discoverable with the expected characteristics
    And the host shares a secure wifi network via bluetooth
    Then viam-agent can reach the app
  Scenario: The agent responds with an error when invalid network credentials are provided during bluetooth provisioning
    When viam-agent is in forced provisioning mode
    And the viam-agent bluetooth device is discoverable with the expected characteristics
    And the host shares invalid wifi credentials for a valid SSID via bluetooth
    Then the viam-agent bluetooth device is discoverable with the expected characteristics again
    And viam-agent surfaces an invalid credentials error via bluetooth
    And viam-agent cannot reach the app