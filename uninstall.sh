#/bin/sh

if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
	FORCE=1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "This install script must be run as root. Try running via sudo."
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

# system services
systemctl disable --now viam-agent
systemctl disable --now viam-server
rm -v /etc/systemd/system/viam-agent.service /etc/systemd/system/viam-server.service

# previous appimage installs
rm -v /usr/local/bin/viam-server

# configs
rm -v /etc/viam.json /etc/viam-provisioning.json

# root/viamdir
rm -vr /root/.viam/

# agent home
rm -vr /opt/viam/

# agent-provisioning customization
rm -v /etc/NetworkManager/conf.d/80-viam.conf /etc/NetworkManager/dnsmasq-shared.d/80-viam.conf
