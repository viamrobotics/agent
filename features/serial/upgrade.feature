Feature: Upgrade viam-agent from stable to the version under test
  Background:
    Given viam-agent is installed at stable
    And viam-agent is pinned to stable
    And the viam-agent systemd unit is running with stable
  Scenario: Pin viam agent to the version under test
    When viam-agent is pinned to the version under test
    Then the viam-agent systemd unit is running with the version under test
    And the viam-agent systemd unit is enabled
