Feature: Uninstall viam-agent
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is running with stable
    And the viam-agent systemd unit is enabled
  Scenario: Uninstall viam-agent
    When viam-agent is uninstalled
    Then the viam-agent systemd unit is dead
    And the viam-agent systemd unit is not found
    And all viam files have been removed
