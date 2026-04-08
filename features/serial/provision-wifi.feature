@darwin
Feature: wifi provisioning
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is enabled
    And the viam-agent systemd unit is running
  # Scenario: The agent enters automatic provisioning mode when expected
  #   When there are no available wifi networks
  #   And viam-agent cannot reach the app
  #   And the provisioning hotspot comes up within 120 seconds
  # Scenario: The agent can join an unknown insecure network when one is provided during wifi hotspot provisioning
  #   When there are no available wifi networks
  #   And viam-agent cannot reach the app
  #   And viam-agent is in forced provisioning mode
  #   And the provisioning hotspot comes up
  #   And the tester shares an insecure wifi network
  #   Then the provisioning hotspot goes away
  #   And viam-agent can reach the app
  Scenario: The agent can join an unknown secure network when one is provided during wifi hotspot provisioning
    When there are no available wifi networks
    And viam-agent cannot reach the app
    And viam-agent is in forced provisioning mode
    And the provisioning hotspot comes up
    And the tester shares a secure wifi network
    Then the provisioning hotspot goes away
    And viam-agent can reach the app
  # Scenario: The agent can join a known secure network when one is provided during wifi hotspot provisioning
  #   When viam-agent is in forced provisioning mode
  #   And the provisioning hotspot comes up
  #   And the tester shares a secure wifi network
  #   Then the provisioning hotspot goes away
  #   And viam-agent can reach the app
  # Scenario: Fail to connect to a network and revert to provisioning hotspot mode
  #   When there are no available wifi networks
  #   And viam-agent cannot reach the app
  #   And viam-agent is in forced provisioning mode
  #   And the provisioning hotspot comes up
  #   And the tester shares an invalid wifi network
  #   Then the provisioning hotspot comes up again
  #   And viam-agent cannot reach the app
