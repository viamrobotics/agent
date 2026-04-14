@darwin
Feature: bluetooth provisioning
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is enabled
    And the viam-agent systemd unit is running
    And there are no available wifi networks
    And viam-agent cannot reach the app
  Scenario: The agent can join an unknown secure network when one is provided during bluetooth provisioning
    When viam-agent is in forced provisioning mode
    # And the viam-agent bluetooth device is discoverable
    And the host shares a secure wifi network via bluetooth
  