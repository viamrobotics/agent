Feature: wifi provisioning
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is enabled
    And the viam-agent systemd unit is running
  Scenario: The agent can join a secure network when one is provided during hotspot provisioning
    When there are no available wifi networks
    Then the provisioning hotspot comes up within 120 seconds
    # And the tester is connected to the provisioning hotspot
    And the tester shares a secure wifi network
    # Then viam-agent connects to the secure wifi network
    # And the provisioning hotspot goes down
    # And viam-agent is online
  # Scenario: Connect to an insecure network
  # Scenario: Fail to connect to a network and revert to provisioning hotspot mode