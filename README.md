# Viam Agent
A self-updating service manager that maintains the lifecycle for viam-server (as built from RDK) and other Viam provided system services.

For more information, see the [Viam Agent documentation](https://docs.viam.com/configure/agent/).

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
Agent can be run directly (`./viam-agent`) outside of systemd for local development purposes. It will only manage viam-server by default. Network and system configuration management can be enabled with `--enable-networking` and `--enable-syscfg`. `--viam-dir` can be used to override the default `/opt/viam` location. See `--help` for the full list of options.

### Systemd
Agent is designed to run as a systemd service. First-time setup is `sudo ./viam-agent --install` and it will automatically update itself when new updates are released.

The service configration lives in both `viam-agent.service` and `preinstall.sh`, and the two should be kept in sync when making changes.
