<<<<<<< HEAD
Feature: uninstall viam-agent
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is running
=======
Feature: Uninstall viam-agent
  Background:
    Given viam-agent is installed
    And the viam-agent systemd unit is running with stable
>>>>>>> 90ed3ca (Add uninstall feature test)
    And the viam-agent systemd unit is enabled
  Scenario: Uninstall viam-agent
    When viam-agent is uninstalled
    Then the viam-agent systemd unit is dead
    And the viam-agent systemd unit is not found
<<<<<<< HEAD
    And the viam files have all been removed
=======
    And all viam files have been removed
>>>>>>> 90ed3ca (Add uninstall feature test)
