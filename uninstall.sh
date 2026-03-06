#/bin/sh

if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
	FORCE=1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "This uninstall script must be run as root. Try running via sudo."
	exit 1
fi

OS=$(uname -s)
if ! [ "$OS" = "Linux" -o "$OS" = "Darwin" ]; then
	echo "This uninstall script can only be run on Linux or MacOS."
	echo
	echo "Please see https://docs.viam.com/manage/reference/viam-agent/manage-viam-agent/ to uninstall on other platforms."
	exit 1
fi

echo
echo "This script completely removes all viam software and any/all cached configuration (At least known about at the time of this script's last update.)"
echo
echo "You will need to completely reinstall and reconfigure this device for use with Viam again in the future!"

if [ -z "$FORCE" ]; then
	echo && echo
	read -p "Remove ALL Viam services, configs, and software? (y/n): " REMOVE_OLD
	if [ "$REMOVE_OLD" != "y" ]; then
		echo "Removal cancelled."
		exit 1
	fi
fi

if [ $OS = "Linux" ]; then
	# systemd services
	systemctl disable --now viam-agent
	systemctl disable --now viam-server
	rm -v /etc/systemd/system/viam-agent.service /usr/local/lib/systemd/system/viam-agent.service /etc/systemd/system/viam-server.service
	systemctl daemon-reload

	# previous appimage installs
	rm -v /usr/local/bin/viam-server

	# agent-provisioning customization
	rm -v /etc/NetworkManager/conf.d/80-viam.conf /etc/NetworkManager/dnsmasq-shared.d/80-viam.conf

	# journald configuration
	rm -v /etc/systemd/journald.conf.d/90-viam.conf

	# provisioning and default configs
	rm -v /etc/viam-provisioning.json /etc/viam-defaults.json

	# root/viamdir
	rm -vr /root/.viam/
else
	# launchd daemon
	launchctl bootout system/com.viam.agent
	rm -v /Library/LaunchDaemons/com.viam.agent.plist

	# root/viamdir
	rm -vr /var/root/.viam/
fi

# config
rm -v /etc/viam.json

# agent home
rm -vr /opt/viam/
