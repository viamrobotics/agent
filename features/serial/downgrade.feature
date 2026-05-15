Feature: Downgrade viam-agent from the version under test to stable
  Background:
    Given viam-agent is installed at the version under test
    And viam-agent is pinned to the version under test
    And the viam-agent systemd unit is running with the version under test
  Scenario: Pin viam agent to an old version
    When viam-agent is pinned to an old version
    Then the viam-agent systemd unit is running with an old version
    And the viam-agent systemd unit is enabled
