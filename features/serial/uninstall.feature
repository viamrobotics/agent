Feature: uninstall viam-agent
  Background:
    Given viam-agent is installed at the version under test
    And the viam-agent systemd unit is running with the version under test
    And the viam-agent systemd unit is enabled
  Scenario: Uninstall viam-agent
    When viam-agent is uninstalled
    Then the viam-agent systemd unit is dead
    And the viam-agent systemd unit is not found
    And the viam files have all been removed
