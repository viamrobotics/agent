Feature: Pinning viam-agent to a viam-server binary is rejected

  Background:
    Given viam-agent is installed at the version under test
    And viam-agent is pinned to the version under test
    And the viam-agent systemd unit is running with the version under test

  Scenario: Pinning viam-agent to a viam-server binary is rejected
    When viam-agent is pinned to a viam-server binary
    Then viam-agent rejected the invalid binary
    And the viam-agent systemd unit is running with the version under test
