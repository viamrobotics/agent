Feature: Pin viam-server to an old version via a URL

  Background:
    Given viam-agent is installed at the version under test
    And the viam-agent systemd unit is running with the version under test
    And viam-server is pinned to stable

  Scenario: Pin viam-server to an old version via a URL
    When viam-server is pinned to a url
    Then viam-server is running with an old version
