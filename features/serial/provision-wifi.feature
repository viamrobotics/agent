Feature: wifi provisioning
  Background:
    Given viam-agent is installed
    # And there are no available wifi networks
    And the viam-agent systemd unit is enabled
    And the viam-agent systemd unit is running
  Scenario: Connect to a secure network
    When the viam-agent systemd unit is enabled
  # When the provisioning hotspot is up
  # And the tester is connected to the provisioning hotspot
  # And the tester shares a secure wifi network
  # Then viam-agent connects to the secure wifi network
  # And the provisioning hotspot goes down
  # And viam-agent can reach the app
  Scenario: Connect to an insecure network
  Scenario: Fail to connect to a network and revert to provisioning hotspot mode