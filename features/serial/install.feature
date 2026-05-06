Feature: install viam-agent
  Background:
    Given viam-agent is not installed
  Scenario: Install the viam-agent version under test
    When viam-agent is installed at the version under test
    Then the viam-agent systemd unit is running with the version under test
    And the viam-agent systemd unit is enabled
    And the journald config is live
    And the wifi power save config is live
