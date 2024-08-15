# Viam Agent
A self-updating service manager that maintains the lifecycle for viam-server (as built from RDK) and other Viam provided system services.

## Requirements
Currently, viam-agent is only supported on Linux, for amd64 (x86_64) and arm64 (aarch64) CPUs.

## Installation
Your system will need to have `curl` available.

### Automatic
The smart machine config `/etc/viam.json` can be installed automatically if you have an API key and part ID available. Modify the following command by inserting your actual details. (Be sure to remove the surrounding < > characters of the placeholders.)
```
sudo /bin/sh -c "VIAM_API_KEY_ID=<KEYID> VIAM_API_KEY=<KEY> VIAM_PART_ID=<PARTID>; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"
```
### Manual configuration
Make sure you've already installed your robot's configuration file to `/etc/viam.json` then run the following:
```
sudo /bin/sh -c "$(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"
```

## Provisioning and Networking
The current version of viam-agent includes a device provisioning subsystem that can help set up wifi and smart machine configs. For more info, see the [Provisioning Subsystem](https://github.com/viamrobotics/agent-provisioning)

## Management
Viam Agent will install itself as a systemd service named `viam-agent`. Start/stop/restart it with `systemctl`  
Ex: `sudo systemctl restart viam-agent`

### Notes
The agent will automatically update both itself and viam-server. However, it is up to the user to restart the service to use the new version.  
For the agent itself restart the service (per the management command above) or reboot. Note this will restart viam-server as well.  
viam-server may be restarted via the normal "restart" button in the cloud App, or as part of the full agent restart per above.  

### Uninstall
To remove the agent and all viam configuration completely, run the following script.
```
sudo /bin/sh -c "$(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/uninstall.sh)"
```

## Configuration
Configuration is maintained via the "agent" section of the device's config in the viam App. Below is an example config section:
```
{
  "agent": {
    "viam-agent": {
      "release_channel": "stable",
      "pin_version": "1.2.3",
      "pin_url": "http://example/test.binary",
      "disable_subsystem": false
    },
    "viam-server": {
      "attributes": {
        "fast_start": true
      }
    },
    "agent-provisioning": {
      "release_channel": "stable"
    },
    "agent-syscfg": {
      "release_channel": "stable"
    }
  }
}
```
Above there are (currently) four subsystems, `viam-agent` (the main agent program itself), `viam-server` (the core of the robot/device), `agent-provisioning` (provides early setup and network management. [Provisioning Details](https://github.com/viamrobotics/agent-provisioning) ), and `agent-syscfg` (provides various OS/system configuration tweaks [Syscfg Details](https://github.com/viamrobotics/agent-syscfg))

Each section primarily controls updates for that subsystem, using one of three settings, `pin_url` (highest priority), `pin_version` (checked/used only if pin_url is unset or empty), and `release_channel` (used by default, and defaults to stable, but only if `pin_url` and `pin_version` are both unset.) The example above gives all three for visual clarity, but is not actually needed. In this case, only `pin_url` would be used.

For release channel, "stable" generally means semantically versioned releases that are tested before release, and are relatively infrequent, but will automatically upgrade when a new version is released. Using `pin_version` allows one to "lock" the subsystem to an explcit version (as provided by the release channel) no automatic upgrades will be performed until the setting is updated to a new version (or removed to revert to the release channel.) Lastly, `pin_url` can be used to point to a specific binary. Typically this is only used for testing/troubleshooting.

The `disable_subsystem` setting can be set to true if you don't wish to use/start a particular subsystem.

Note that only sections/settings you explicitly want to modify need to be included in the config. By default, all subsystems will use the `stable` release channel, so no configuration at all is needed to get that behavior. E.g. in the example above, viam-server will still get stable releases, as none of the update-related values are being modified, but it will ALSO use the fast_start behavior detailed below. For another example, the `agent-provisioning` or `agent-syscfg` sections could be left out entirely, and the device will use a default config for those subsystems anyway. To actually disable one, the section can be added, and `disable_subsystem` to to `true`


## FastStart Mode
This bypasses the normal network/online wait and update checks during inital startup, and executes viam-server as quickly as possible. Useful if you have a device that often starts when offline or on a slow connection, and having the latest version immediately after start isn't required. Note that normal, periodic update checks will continue to run afterwards. This only affects initial startup sequencing.

To use it, set `"fast_start": true` in the attributes for the viam-server subsystem. Alternately, set `VIAM_AGENT_FAST_START=1` in your environment.

## Development

### Makefile Targets
* `make` will build a viam-agent for your current CPU architecture. Note that as only linux is supported, this will be a linux binary.  
* `make arm64` arm64 specific build.
* `make amd64` amd64 specific.  
* `make all` will build for all (both) supported architectures.  
* `make lint` to lint.

### Version Tagging
The makefile will attempt to get a tagged version from Git. If you want to manually force a version, set `TAG_VERSION=0.1.2` in the make command.  
Note that there is no "v" in the actual version, though it is expected in git. E.g. a git tag of `v0.1.2` becomes `TAG_VERSION=0.1.2`  
Ex: `make all TAG_VERSION=0.1.2`

### DevMode
Setting the environment variable `VIAM_AGENT_DEVMODE=1` will skip the self-location check for the binary, so you can run it directly during development, without installing to /opt/viam.
