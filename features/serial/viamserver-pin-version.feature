Feature: Pin viam-server to an older version

  Background:
    Given viam-agent is installed at the version under test
    And the viam-agent systemd unit is running with the version under test
    And viam-server is pinned to stable

  Scenario: Pin viam-server to an older version
    When viam-server is pinned to an old version
    Then viam-server is running with an old version
