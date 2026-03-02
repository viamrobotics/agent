Feature: Upgrade viam-agent
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is running with stable
  Scenario: Pin viam agent to stable
    When viam-agent is pinned to dev
    Then the viam-agent systemd unit is running with dev
    And the viam-agent systemd unit is enabled
