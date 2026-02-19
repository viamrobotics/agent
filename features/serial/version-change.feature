Feature: change viam-agent versions
  Background:
    Given viam-agent is uninstalled
    And viam-agent is pinned to stable
    And viam-agent is installed
  Scenario: Pin viam agent to an old version
    When viam-agent is pinned to 0.24.2
    Then the viam-agent systemd unit started with 0.24.2
    And the viam-agent systemd unit is running
    And the viam-agent systemd unit is enabled
