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

## FastStart Mode
This bypasses the normal network/online wait and update checks during inital startup, and executes viam-server as quickly as possible. Useful if you have a device that often starts when offline or on a slow connection, and having the latest version immediately after start isn't required. Note that normal, periodic update checks will continue to run afterwards. This only affects initial startup sequencing.

To use it, set "VIAM_AGENT_FASTSTART=1" in your environment. To make this permanent for the systemd service, run `sudo systemctl edit viam-agent` and insert the following override chunk:

```
[Service]
Environment=VIAM_AGENT_FASTSTART=1
```

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
