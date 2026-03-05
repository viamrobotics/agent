Feature: Pinning viam-agent to a viam-server binary is rejected

  Background:
    Given viam-agent is installed
    And viam-agent is pinned to stable
    And the viam-agent systemd unit is running with stable

  Scenario: Pinning viam-agent to a viam-server binary is rejected
    When viam-agent is pinned to a viam-server binary
    Then viam-agent rejected the invalid binary
    And the viam-agent systemd unit is running with stable
