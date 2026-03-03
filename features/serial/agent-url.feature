Feature: Upgrade viam-agent via custom URL and file sources

  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is running with stable

  Scenario: Pin viam-agent to an old version via a URL
    When viam-agent is pinned to a url
    Then the viam-agent systemd unit is running with an old version

  Scenario: Pin viam-agent to an old version via a local file
    Given an old viam-agent binary is present on the device
    When viam-agent is pinned to a file
    Then the viam-agent systemd unit is running with an old version

  Scenario: Pinning viam-agent to a viam-server binary is rejected
    When viam-agent is pinned to a viam-server binary
    Then the viam-agent systemd unit is running with stable
