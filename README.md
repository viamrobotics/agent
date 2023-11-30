# Viam Agent
A self-updating service manager that maintains the lifecycle for viam-server (as built from RDK) and other Viam provided system services.

## Requirements
Currently, viam-agent is only supported on Linux, for amd64 (x86_64) and arm64 (aarch64) CPUs.

## Installation
Make sure you've already installed your robot's configuration file to `/etc/viam.json` and have `curl` availible, then simply run the following:
```
sudo /bin/sh -c "$(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"
```
Files will be placed in `/opt/viam` and a service file at `/etc/systemd/system/viam-agent.service`

## Management
Viam Agent will install itself as a systemd service named `viam-agent`. Start/stop/restart it with `systemctl`  
Ex: `sudo systemctl restart viam-agent`

### Notes
The agent will automatically update both itself and viam-server. However, it is up to the user to restart the service to use the new version.  
For the agent itself restart the service (per the management command above) or reboot. Note this will restart viam-server as well.  
viam-server may be restarted via the normal "restart" button in the cloud App, or as part of the full agent restart per above.  

### Uninstall
To remove the agent completely, simply stop the service and remove the files mentioned above.  
```
sudo systemctl disable --now viam-agent
sudo rm -rf /opt/viam /etc/systemd/system/viam-agent.service
sudo systemctl daemon-reload
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
