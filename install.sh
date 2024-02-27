#!/bin/sh

# This script installs viam-agent. It is intended to be run directly from a download, with a command such as:
# sudo /bin/sh -c "$(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"

# The preferred command should be copy/pasted from the robot's setup tab on app.viam.com
# It should auto-generate a command in the following format (with key/id info filled in)
# sudo /bin/sh -c "VIAM_API_KEY_ID=<KEYID> VIAM_API_KEY=<KEY> VIAM_PART_ID=<PARTID>; $(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/install.sh)"


ARCH=$(uname -m)
URL="https://storage.googleapis.com/packages.viam.com/apps/viam-agent/viam-agent-stable-$ARCH"
PROVISIONING_URL="https://storage.googleapis.com/packages.viam.com/apps/viam-agent-provisioning/viam-agent-provisioning-stable-$ARCH"

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
			echo "Installation cancelled."
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

# Verifies that NetworkManager is 1.42 or newer.
check_nm_version() {
	which nmcli >/dev/null 2>&1 || return 1

	NM_VERSION=$(nmcli --version | grep -Eo '[0-9]+.[0-9]+.[0-9]+')

	NM_VERSION_MAJOR=$(echo $NM_VERSION | cut -d. -f1)
	NM_VERSION_MINOR=$(echo $NM_VERSION | cut -d. -f2)

	if [ $NM_VERSION_MAJOR -ge 1 ] && [ $NM_VERSION_MINOR -ge 42 ]; then
		return 0
	fi

	return 1
}

is_bullseye() {
	grep -q VERSION_CODENAME=bullseye /etc/os-release
}

add_network() {
	if [ "$SSID" != "" ]; then
		echo "Migrating $SSID connection settings"

		FILENAME=

		if [ "$PSK" != "" ]; then
			nmcli --offline con add connection.id "$SSID" connection.type 802-11-wireless 802-11-wireless.ssid "$SSID" 802-11-wireless-security.key-mgmt wpa-psk 802-11-wireless-security.psk "$PSK" > /etc/NetworkManager/system-connections/"$SSID.nmconnection"
		else
			nmcli --offline con add connection.id "$SSID" connection.type 802-11-wireless 802-11-wireless.ssid "$SSID" > /etc/NetworkManager/system-connections/"$SSID.nmconnection"
		fi
	fi
}

migrate_wpa_conf() {
	NETWORK=0
	SSID=""
	PSK=""

	while read -r line; do
		if echo $line | grep -qE 'network[[:space:]]?='; then
			NETWORK=$(( NETWORK + 1 ))
			add_network
			SSID=""
			PSK=""
		elif echo $line | grep -qE 'ssid[[:space:]]?='; then
			SSID=$(echo $line | cut -d= -f2 | tr -d \")
		elif echo $line | grep -qE 'psk[[:space:]]?='; then
			PSK=$(echo $line | cut -d= -f2 | tr -d \")
		fi
	done < /etc/wpa_supplicant/wpa_supplicant.conf
	add_network
	chmod 600 /etc/NetworkManager/system-connections/*.nmconnection
}

warn_nonm(){
		echo
		echo "Please manually install/activate NetworkManager to use network/provisioning services. Until then, you may notice errors in your logs regarding this."
		echo
		echo "You may disable the \"agent-provisioning\" subsystem in your device's config to avoid these."
		echo
		echo "To do so, click the \"Raw Json\" on the \"Config\" tab for your device at https://app.viam.com/ and set \"disable_subsystem\" to \"true\" and save"
		echo
		echo "This should not affect other Viam services, nor viam-server itself."
}

# Attempts to enable NetworkManager (only tested on Raspberry PiOS/Bullseye)
enable_networkmanager() {
	systemctl is-enabled NetworkManager && check_nm_version && return

	echo
	echo "Viam provides a wifi management and device provisioning service. To use it, NetworkManager 1.42 (or newer) must be installed and active."

	if check_nm_version || is_bullseye; then
		# We can automate this.
		echo
		echo "This script can attempt to upgrade/activate NetworkManager for you, but may potentially break your existing network configuration."
		echo
		echo "It will attempt to migrate any existing wifi connections from wpa_supplicant, but may not always work."
		echo
		echo "If you are connected through SSH via WiFi, you may be disconnected. If this happens, please wait several minutes to see if the connection resumes."
		echo
		echo "If after 5 minutes, you remain disconnected, please look for a provisioning hotspot to join. You may need to reboot for this to appear."

		if [ -z "$FORCE" ]; then
			echo && echo
			read -p "Proceed with NetworkManager upgrade/activation? (y/n): " DO_NM_INSTALL
			if [ "$DO_NM_INSTALL" != "y" ]; then
				echo "NetworkManager upgrade/activation skipped."
				warn_nonm
				return 1
			fi
		fi
	else
		# We can't automate this.
		warn_nonm()
		return 1
	fi

	echo
	echo "Pre-installing provisioning subsystem as a backup."

	mkdir -p /opt/viam/bin /opt/viam/tmp
	cd /opt/viam/tmp && curl -fL -o viam-agent-provisioning-temp-$ARCH "$PROVISIONING_URL" && \
	chmod 755 viam-agent-provisioning-temp-$ARCH && ln -s /opt/viam/tmp/viam-agent-provisioning-temp-$ARCH ../bin/agent-provisioning


	if is_bullseye; then
		echo 'deb http://deb.debian.org/debian/ bullseye-backports main' > /etc/apt/sources.list.d/backports.list && \
		apt update && apt install -y network-manager/bullseye-backports || (echo "Failed to upgrade NetworkManager" && return 1)
	fi

	if [ -f "/etc/wpa_supplicant/wpa_supplicant.conf" ]; then
		migrate_wpa_conf
	fi

	if systemctl cat NetworkManager >/dev/null; then
		systemctl enable --now NetworkManager || (echo "Failed to active NetworkManager" && return 1)
		systemctl disable dhcpcd
	else
		return 1
	fi

	n=1
	while [ "$n" -le 30 ]; do
		systemctl is-enabled NetworkManager && break
		n=$(( n + 1 ))
		sleep 1
	done

	if ! systemctl is-enabled NetworkManager; then
		echo
		echo "Error: Was unable to activate NetworkManager."
		return 1
	fi

	nmcli g reload

	return 1
}

# Main
main() {
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
		echo "Viam agent may fail to fully start, or may immediately enter provisioning mode after installation, which will disconnect wifi."
		echo
		echo "It is recommended that you re-run this installer with the exact command (including API keys) provided on the \"Setup\" tab for your robot at https://app.viam.com/"
		echo
		echo "Alternately, manually install /etc/viam.json, then re-run this installation."

		if [ -z "$FORCE" ]; then
			echo && echo
			read -p "Continue anyway (not recommended)? (y/n): " CONTINUE
			if [ "$CONTINUE" != "y" ]; then
				echo "Installation aborted."
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
				echo "Installation aborted."
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

	./viam-agent-temp-$ARCH --install
	if [ $? -ne 0 ]; then
		echo
		echo "Error installing viam-agent. Please correct any errors mentioned above and try again."
		exit 2
	fi

	enable_networkmanager

	systemctl restart viam-agent

	echo && echo && echo
	echo "Viam Agent installed successfully. You may start/stop/restart it via systemd's 'systemctl' command."
	echo "Example: 'systemctl restart viam-agent'"
	echo
	echo "It has already been started for you and set to start automatically at boot time."
}

main
