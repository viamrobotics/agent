Feature: Pin viam-server to an older version

  Background:
    Given viam-agent is installed
    And viam-agent is pinned to stable
    And viam-server is pinned to stable
    And the viam-agent systemd unit is running with stable

  Scenario: Pin viam-server to an older version
    When viam-server is pinned to an old version
    Then viam-server is running with an old version
