Feature: Change viam-server version

  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is running with stable

  Scenario: Pin viam-server to an older version
    When viam-server is pinned to an old version
    Then viam-server is running with an old version

  Scenario: Pin viam-server to an old version via a URL
    When viam-server is pinned to a url
    Then viam-server is running with an old version

  Scenario: Pin viam-server to an old version via a local file
    Given an old viam-server binary is present on the device
    When viam-server is pinned to a file
    Then viam-server is running with an old version
