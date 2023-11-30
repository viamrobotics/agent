#!/bin/sh

# This script installs viam-agent. It is intended to be run directly from a download, with a command such as:
# sudo /bin/sh -c "$(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"

ARCH=$(uname -m)
URL="https://storage.googleapis.com/packages.viam.com/apps/viam-agent/viam-agent-stable-$ARCH"

# Force will bypass all prompts by treating them as yes. May also be set as an environment variable when running as download.
# sudo /bin/sh -c "FORCE=1; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"
if [ "$1" == "--force" ] || [ "$1" == "-f" ]; then
	FORCE=1
fi

# Removes previous viam-server service as installed from AppImage.
uninstall_old_service() {
	if ! [ -f /etc/systemd/system/viam-server.service ]; then
		return
	fi

	echo "A previous install of viam-server has been detected. It needs to be removed before proceeding."
	echo "Note: This will only remove the installed binary and service files. Your /etc/viam.json config will be left in place."
	
	if [ -z "$FORCE" ]; then
		read -p "Remove previous viam-server service? (y/n): " REMOVE_OLD
		if [ "$REMOVE_OLD" != "y" ]; then
			exit 1
		fi
	fi

	systemctl disable --now viam-server || echo "Error disabling previous service" && exit 2
	rm -f /etc/systemd/system/viam-server.service /usr/local/bin/viam-server
	systemctl daemon-reload
	return
}

# Main
if [ "$(uname -s)" != "Linux" ] || ! [ "$ARCH" == "x86_64" -o "$ARCH" == "aarch64" ]; then
	echo "Viam Agent is currently only available for Linux on x86_64 (amd64) and aarch64 (arm64)."
	echo "Please see https://docs.viam.com/get-started/installation/ to install on other platforms."
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "This install script must be run as root. Try running via sudo."
	exit 1
fi

if ! [ -d /etc/systemd/system ]; then
	echo "Viam Agent is only supported on systems using systemd."
	exit 1
fi

if [ -f /etc/systemd/system/viam-agent.service ]; then
	echo "It appears viam-agent is already installed."
	echo "You can restart it with 'systemctl restart viam-agent' if it's not running."
	echo "If it's not starting, make sure you have a valid config at /etc/viam.json first."

	if [ -z "$FORCE" ]; then
		echo && echo
		read -p "Force reinstall anyway? (y/n): " DO_REINSTALL
		if [ "$DO_REINSTALL" != "y" ]; then
			exit 1
		fi
	fi

	systemctl stop viam-agent
	if [ $? -ne 0 ]; then
		echo "Error stopping existing viam-agent service for reinstall."
		exit 2
	fi
fi

if ! [ -f /etc/viam.json ]; then
	echo "No configuration file found at /etc/viam.json"
	echo "It is recommended that you install the config file first."

	if [ -z "$FORCE" ]; then
		read -p "Continue anyway? (y/n): " CONTINUE
		if [ "$CONTINUE" != "y" ]; then
			exit 1
		fi
	fi
fi

uninstall_old_service

mkdir -p /opt/viam/tmp && cd /opt/viam/tmp && curl -fL -o viam-agent-temp-$ARCH "$URL" && chmod 755 viam-agent-temp-$ARCH
if [ $? -ne 0 ]; then
	echo "Error downloading agent binary. Please correct any errors mentioned above and try again."
	exit 2
fi

./viam-agent-temp-$ARCH --install && systemctl restart viam-agent
if [ $? -ne 0 ]; then
	echo "Error installing viam-agent. Please correct any errors mentioned above and try again."
	exit 2
fi

systemctl restart viam-agent

echo && echo && echo
echo "Viam Agent installed successfully. You may start/stop/restart it via systemd's 'systemctl' command."
echo "Example: 'systemctl restart viam-agent'"
echo "It has already been started for you and set to start automatically at boot time."
echo "If you did not already have a config file in place at /etc/viam.json you may need to restart the service after adding one."
