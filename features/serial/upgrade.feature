Feature: Upgrade viam-agent
  Background:
    Given viam-agent is installed
    And viam-agent is pinned to an old version
    Then the viam-agent systemd unit is running with an old version
  Scenario: Pin viam agent to stable
    When viam-agent is pinned to stable
    Then the viam-agent systemd unit is running with stable
    And the viam-agent systemd unit is enabled
