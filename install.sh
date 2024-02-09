#!/bin/sh

# This script installs viam-agent. It is intended to be run directly from a download, with a command such as:
# sudo /bin/sh -c "$(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"

# The preferred command should be copy/pasted from the robot's setup tab on app.viam.com
# It should auto-generate a command in the following format (with key/id info filled in)
# sudo /bin/sh -c "VIAM_API_KEY_ID=<KEYID> VIAM_API_KEY=<KEY> VIAM_PART_ID=<PARTID>; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"


ARCH=$(uname -m)
URL="https://storage.googleapis.com/packages.viam.com/apps/viam-agent/viam-agent-stable-$ARCH"

# Force will bypass all prompts by treating them as yes. May also be set as an environment variable when running as download.
# sudo /bin/sh -c "FORCE=1; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
	FORCE=1
fi

# Removes previous viam-server service as installed from AppImage.
uninstall_old_service() {
	if ! [ -f /etc/systemd/system/viam-server.service ]; then
		return
	fi

	echo 
	echo "A previous install of viam-server has been detected. It needs to be removed before proceeding."
	echo
	echo "Note: This will only remove the installed binary and service files. Your /etc/viam.json config will be left in place."
	
	if [ -z "$FORCE" ]; then
		echo && echo
		read -p "Remove previous viam-server service? (y/n): " REMOVE_OLD
		if [ "$REMOVE_OLD" != "y" ]; then
			exit 1
		fi
	fi

	systemctl disable --now viam-server || (echo "Error disabling previous service" && exit 2)
	rm -f /etc/systemd/system/viam-server.service /usr/local/bin/viam-server
	systemctl daemon-reload
	return
}

# Uses API keys and ID provided as env vars to fetch and install /etc/viam.sjon
fetch_config() {
	if [ "$VIAM_API_KEY_ID" != "" ] && [ "$VIAM_API_KEY" != "" ] && [ "$VIAM_PART_ID" != "" ]; then
		curl -fsSL \
			-H "key_id:$VIAM_API_KEY_ID" \
			-H "key:$VIAM_API_KEY" \
			"https://app.viam.com/api/json1/config?client=true&id=$VIAM_PART_ID" \
			-o /etc/viam.json
	fi
}

# Attempts to enable NetworkManager (only tested on Raspberry PiOS/Bullseye)
enable_networkmanager() {
	systemctl is-enabled NetworkManager && return

	echo
	echo "Viam provides a wifi management and device provisioning service. To use it, NetworkManager must be installed and active."

	if systemctl cat NetworkManager >/dev/null; then
		echo
		echo "It appears NetworkManager is installed but not enabled."
		echo "This script can activate it for you, but may potentially break your existing network configuration."
		echo
		echo "It may also TEMPORARILY disconnect you from your device if you are connected remotely (ssh or similar.)"
		echo "If that happens, please WAIT 5 minutes for connectivity to resume."
		echo
		echo "If connections are not restored after 5 minutes, please see if a provisioning hotspot has beens started by the device."
		echo "As a last resort, you should reboot your device and see if connectivity (or a hotspot) is restored."

		if [ -z "$FORCE" ]; then
			echo && echo
			read -p "Proceed with NetworkManager installation? (y/n): " DO_NM_INSTALL
			if [ "$DO_NM_INSTALL" != "y" ]; then
				return 1
			fi
		fi

		echo
		echo "Waiting for viam-agent to fully start."
		n=1
		while [ "$n" -le 5 ]; do
			# if we mess up the networking, we want provisioning to be installed as a backup
			if [ -e "/opt/viam/bin/agent-provisioning" ]; then
				sleep 5
				break
			fi
			n=$(( n + 1 ))
			sleep 5
		done

		systemctl enable --now NetworkManager && systemctl disable dhcpcd

		n=1
		while [ "$n" -le 30 ]; do
			systemctl is-enabled NetworkManager && break
			n=$(( n + 1 ))
			sleep 1
		done

		if ! systemctl is-enabled NetworkManager; then
			echo
			echo "Error: Was unable to activate NetworkManager."
			exit 1
		fi

		if which perl >/dev/null; then
			ssid=$(perl -lne 'print $1 if /ssid="?([^"]+)"?/' < /etc/wpa_supplicant/wpa_supplicant.conf | head -n1)
			psk=$(perl -lne 'print $1 if /psk="?([^"]+)"?/' < /etc/wpa_supplicant/wpa_supplicant.conf | head -n1)
		fi
		if [ "$ssid" != "" ]; then
			if [ "$psk" != "" ]; then
				pass_string="password "
			fi

			n=1
			while [ "$n" -le 5 ]; do
				echo
				echo "Attempting to migrate wifi settings for SSID $ssid"
				echo "Attempt $n of 5"

				nmcli dev wifi list --rescan yes > /dev/null
				nmcli device wifi connect "$ssid" $pass_string "$psk" && break
				n=$(( n + 1 ))
				sleep 5
			done
		fi

		echo
		echo "If your wifi network was not shown as migrated above, you should add it manually before rebooting."
		echo
		echo "Ex: 'nmcli device wifi connect <SSID> password <PASSWORD>'"
	fi

	echo
	echo "Please manually install/activate NetworkManager to use network/provisioning services. Until then, you may notice errors in your logs regarding this."
	echo
	echo "You may disable the \"agent-provisioning\" subsystem in your device's config to avoid these."
	echo 
	echo "To do so, click the \"Raw Json\" on the \"Config\" tab for your device at https://app.viam.com/ and set \"disable_subsystem\" to \"true\" and save"
	return 1
}

# Main
if [ "$(uname -s)" != "Linux" ] || ! [ "$ARCH" = "x86_64" -o "$ARCH" = "aarch64" ]; then
	echo
	echo "Viam Agent is currently only available for Linux on x86_64 (amd64) and aarch64 (arm64)."
	echo
	echo "Please see https://docs.viam.com/get-started/installation/ to install on other platforms."
	exit 1
fi

if ! [ -d /etc/systemd/system ]; then
	echo
	echo "Viam Agent is only supported on systems using systemd."
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo
	echo "This install script must be run as root. Try running via sudo."
	exit 1
fi

# Attempt to fetch the config using API keys (if set)
fetch_config

if ! [ -f /etc/viam.json ]; then
	echo
	echo "WARNING: No configuration file found at /etc/viam.json and no (valid) API keys were provided to automatically download one."
	echo
	echo "No Viam services will be available until a valid config file is in place."
	echo
	echo "It is recommended that you re-run this installer with the exact command (including API keys) provided on the \"Setup\" tab for your robot at https://app.viam.com/"
	echo
	echo "Alternately, manually install /etc/viam.json, then re-run this installation."

	if [ -z "$FORCE" ]; then
		echo && echo
		read -p "Continue anyway (not recommended)? (y/n): " CONTINUE
		if [ "$CONTINUE" != "y" ]; then
			exit 1
		fi
	fi
fi

uninstall_old_service

if [ -f /etc/systemd/system/viam-agent.service ]; then
	echo
	echo "It appears viam-agent is already installed. You can restart it with 'systemctl restart viam-agent' if it's not running."

	if [ -z "$FORCE" ]; then
		echo && echo
		read -p "Force reinstall anyway? (y/n): " DO_REINSTALL
		if [ "$DO_REINSTALL" != "y" ]; then
			exit 1
		fi
	fi

	systemctl stop viam-agent
	if [ $? -ne 0 ]; then
		echo
		echo "Error stopping existing viam-agent service for reinstall."
		exit 2
	fi
fi

mkdir -p /opt/viam/tmp && cd /opt/viam/tmp && curl -fL -o viam-agent-temp-$ARCH "$URL" && chmod 755 viam-agent-temp-$ARCH
if [ $? -ne 0 ]; then
	echo
	echo "Error downloading agent binary. Please correct any errors mentioned above and try again."
	exit 2
fi

./viam-agent-temp-$ARCH --install && systemctl restart viam-agent
if [ $? -ne 0 ]; then
	echo
	echo "Error installing viam-agent. Please correct any errors mentioned above and try again."
	exit 2
fi

enable_networkmanager

echo && echo && echo
echo "Viam Agent installed successfully. You may start/stop/restart it via systemd's 'systemctl' command."
echo "Example: 'systemctl restart viam-agent'"
echo
echo "It has already been started for you and set to start automatically at boot time."
