Feature: Pin viam-server to an old version via a local file

  Background:
    Given viam-agent is installed
    And viam-agent is pinned to stable
    And viam-server is pinned to stable
    And the viam-agent systemd unit is running with stable

  Scenario: Pin viam-server to an old version via a local file
    Given an old viam-server binary is present on the device
    When viam-server is pinned to a file
    Then viam-server is running with an old version
