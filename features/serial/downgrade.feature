Feature: Downgrade viam-agent
  Background:
    Given viam-agent is uninstalled
    And viam-agent is pinned to stable
    And viam-agent is installed
  Scenario: Pin viam agent to an old version
    When viam-agent is pinned to an old version
    Then the viam-agent systemd unit is running with an old version
    And the viam-agent systemd unit is enabled
