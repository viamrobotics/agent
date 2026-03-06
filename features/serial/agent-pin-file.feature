Feature: Pin viam-agent to an old version via a local file

  Background:
    Given viam-agent is installed
    And viam-agent is pinned to stable
    And the viam-agent systemd unit is running with stable

  Scenario: Pin viam-agent to an old version via a local file
    Given an old viam-agent binary is present on the device
    When viam-agent is pinned to a file
    Then the viam-agent systemd unit is running with an old version
