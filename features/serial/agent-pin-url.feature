Feature: Pin viam-agent to an old version via a URL

  Background:
    Given viam-agent is installed
    And viam-agent is pinned to stable
    And the viam-agent systemd unit is running with stable

  Scenario: Pin viam-agent to an old version via a URL
    When viam-agent is pinned to a url
    Then the viam-agent systemd unit is running with an old version
