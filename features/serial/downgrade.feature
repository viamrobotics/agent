Feature: Downgrade viam-agent
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is running with stable
  Scenario: Pin viam agent to an old version
    When viam-agent is pinned to an old version
    Then the viam-agent systemd unit is running with an old version
    And the viam-agent systemd unit is enabled
