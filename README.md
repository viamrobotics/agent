# Viam Agent
A self-updating service manager that maintains the lifecycle for viam-server (as built from RDK) and other Viam provided system services.

For more information, see the [Viam Agent documentation](https://docs.viam.com/configure/agent/).

Agent is designed to run as a systemd service. First-time setup is `sudo ./viam-agent --install` and it will automatically update itself when new updates are released.

## Development

### Required tools

We use [mise-en-place][mise] to manage `golangci-lint`. In the future this may expand to include other development tools. You can install it on MacOS and most Linux distributions with the following command:

```bash
curl https://mise.run | sh
```

Mise is also available in Homebrew and several package repositories. See the [official documentation][install-mise] for a list of installation methods.

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

### Release Artifact Verification
Each published manifest in `apps/viam-subsystems/` advertises a sha256 that must match the binary its `upload-path` names. The manifest and the binary are written by two separate `gsutil` calls, so concurrent runs building the same version can leave a manifest describing a binary nobody can download — agents targeting that version then reject the download and retry indefinitely.

`./verify-manifests.sh` checks that they agree. It reads published state only, so no credentials are needed:

```bash
./verify-manifests.sh --version v1.0.1   # every platform for one version
./verify-manifests.sh --count 20         # the 20 most recently written manifests
./verify-manifests.sh --count 0          # every release manifest
```

Test and Build runs `--version` against whatever it just published, so a run that writes a manifest always re-reads it. The **Verify Manifests** workflow runs sweeps on demand, for prereleases, full history, or writes made outside CI.

When a mismatch is found, the **Fix Manifest** workflow repairs it. Pick the mode by deciding what the object at `upload-path` actually is: `manifest` when the published binary is the artifact you meant to ship and only the checksum is wrong, `rebuild` when the binary itself is wrong and should be rebuilt from the tag. Note that neither repair unsticks machines that already cached the bad checksum, since `version_control.go` returns early on an unchanged version string — those need a version bump or a cache clear.

### DevMode
Agent can be run directly (`./viam-agent`) outside of systemd for local development purposes. It will only manage viam-server by default. Network and system configuration management can be enabled with `--enable-networking` and `--enable-syscfg`. `--viam-dir` can be used to override the default `/opt/viam` location. See `--help` for the full list of options.

### Systemd
The service configration lives in both `viam-agent.service` and `preinstall.sh`, and the two should be kept in sync when making changes.

### Testing via serial

Some end-to-end workflows can be tested by connecting to a Raspberry Pi with a serial adapter. These tests can be run via a mise task but require additional setup:

- You must have a USB to serial adapter or some other means to connect to the serial port on your Raspberry Pi.
- Your Raspberry Pi must be configured to enable login on the serial port. This can be accomplished with the `raspi-config` cli or by manually editing config files. Refer to the upstream Raspberry Pi docs for details.
    - Instead of using `raspi-config` (which does not appear to work with the Raspberry Pi 5), you can add the following lines to the bottom of `/boot/firmware/config.txt` to enable login on the serial port:
    ```shell
    enable_uart=1
    dtparam=uart0
    dtparam=uart0_console
    ```
- The test framework will attempt to log in to your pi using the credentials supplied in `agent-test.toml` (see below). To test the serial connection we recommend [picocom]. You can use it to connect to the serial terminal and login with `picocom -b 115200 /dev/ttyUSB0`. Depending on your setup the previous command may require sudo and the path to the tty device may be different. To disconnect from the serial console, type `Ctrl-a Ctrl-x`.
- You must have a file named `agent-test.toml` in the root of this repo with app.viam API keys and other values required by the tests. You can also use this file to specify optional parameters, such as the path to the serial device. Refer to `agent-test-example.toml` for details.

Once these dependencies are satisfied you can execute the serial tests with `mise r test-e2e-serial`.

The tests should not require any user input while they are running, aside from maybe accepting a macOS dialog requesting permission to control the network adapter. This test will cause your Mac to connect to the wifi hotspot hosted by the Pi. The captive portal will appear and disappear on its own - you do not need to interact with it.

[mise]: https://mise.jdx.dev/
[install-mise]: https://mise.jdx.dev/installing-mise.html
[picocom]: https://github.com/npat-efault/picocom