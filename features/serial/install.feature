Feature: install viam-agent
  Background:
    Given viam-agent is not installed
  Scenario: Install current stable version of viam-agent
    When viam-agent is installed
    Then the viam-agent systemd unit is running
    And the viam-agent systemd unit is enabled
