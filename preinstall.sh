#!/bin/sh

ARCH=""
ROOTFS=""
BOOTFS=""
IS_PI=0
MOUNTS=""
TEMPDIR=""
TARBALL=""
TARBALL_ONLY=0

SERVICE_FILE=$(cat <<EOF
[Unit]
Description=Viam Services Agent
After=NetworkManager.service network-online.target
Wants=NetworkManager.service network-online.target
StartLimitIntervalSec=0

[Service]
Type=exec
Restart=always
RestartSec=5
User=root
TimeoutSec=120
ExecStart=/opt/viam/bin/viam-agent --config /etc/viam.json
FinalKillSignal=SIGQUIT

[Install]
WantedBy=multi-user.target
EOF
)

find_mountpoints_linux() {
	if [ "$MOUNTS" = "" ]; then
		MOUNTS=$(findmnt -o TARGET -l | grep -v TARGET | grep -vE '^/$')
	fi
}

find_mountpoints_macos() {
	if [ "$MOUNTS" = "" ]; then
		volsplist=$(mktemp)
		diskutil list -plist > "$volsplist"
		vols=$(/usr/libexec/PlistBuddy -c "Print :VolumesFromDisks" "$volsplist" | grep -vE '[{}]' | awk '{$1=$1};1')
		while read -r vol; do
			volplist=$(mktemp)
			diskutil info -plist "$vol" > "$volplist"
			newMount=$(/usr/libexec/PlistBuddy -c "Print :MountPoint" "$volplist")
			if [ "$newMount" != "" ]; then
				MOUNTS=$(echo "$newMount\n$MOUNTS")
			fi
			rm "$volplist"
		done <<-EOF
		$vols
		EOF
		rm "$volsplist"
	fi
	return 0
}

check_fs() {
	echo && echo
	while read -r mount; do
		if stat "$mount/etc/systemd/system" >/dev/null 2>&1; then
			ROOTFS="$mount"
			if stat "$mount/lib64/ld-linux-x86-64.so.2" >/dev/null 2>&1 || stat "$mount/lib/ld-linux-x86-64.so.2" >/dev/null 2>&1; then
				ARCH=x86_64
			fi
			if stat "$mount/lib/ld-linux-aarch64.so.1" >/dev/null 2>&1; then
				ARCH=aarch64
			fi
			echo "Found target filesystem mounted at $ROOTFS with $ARCH"
		fi

		if stat "$mount/firstrun.sh" >/dev/null 2>&1; then
			BOOTFS="$mount"
			IS_PI=1
			ARCH=aarch64
			echo "Found Raspberry Pi bootfs mounted at $BOOTFS"
		fi
	done <<-EOF
	$MOUNTS
	EOF

	if [ "$ARCH" != "" ] && ([ "$ROOTFS" != "" ] || [ "$BOOTFS" != "" ]); then
		return 0
	fi
	return 1
}

create_tarball() {
	echo "Creating tarball for install."
	URL="https://storage.googleapis.com/packages.viam.com/apps/viam-agent/viam-agent-stable-$ARCH"
	PROVISIONING_URL="https://storage.googleapis.com/packages.viam.com/apps/viam-agent-provisioning/viam-agent-provisioning-stable-$ARCH"

	TEMPDIR=$(mktemp -d)

	mkdir -p "$TEMPDIR/etc/systemd/system/multi-user.target.wants/"
	echo "$SERVICE_FILE" > "$TEMPDIR/etc/systemd/system/viam-agent.service"
	ln -s /etc/systemd/system/viam-agent.service "$TEMPDIR/etc/systemd/system/multi-user.target.wants/viam-agent.service"

	mkdir -p "$TEMPDIR/opt/viam/cache"
	curl -fsSL "$URL" -o "$TEMPDIR/opt/viam/cache/viam-agent-factory-$ARCH" || return 1
	curl -fsSL "$PROVISIONING_URL" -o "$TEMPDIR/opt/viam/cache/viam-agent-provisioning-factory-$ARCH" || return 1
	chmod 755 "$TEMPDIR/opt/viam/cache/viam-agent-factory-$ARCH" "$TEMPDIR/opt/viam/cache/viam-agent-provisioning-factory-$ARCH"

	mkdir -p "$TEMPDIR/opt/viam/bin"
	ln -s "/opt/viam/cache/viam-agent-factory-$ARCH" "$TEMPDIR/opt/viam/bin/viam-agent"
	ln -s "/opt/viam/cache/viam-agent-provisioning-factory-$ARCH" "$TEMPDIR/opt/viam/bin/agent-provisioning"

	if [ -f "$PROVISIONING_PATH" ]; then
	        echo "Installing $PROVISIONING_PATH as /etc/viam-provisioning.json"
		cat "$PROVISIONING_PATH" > "$TEMPDIR/etc/viam-provisioning.json"
	fi

	TARBALL="$TEMPDIR/viam-preinstall-$ARCH.tar.xz"
	tar -cJvpf "$TARBALL" -C "$TEMPDIR" opt/ etc/ || return 1
}

if [ "$(id -u)" -ne 0 ]; then
	echo
	echo "This install script must be run as root. Try running via sudo."
	exit 1
fi

if ! [ -z $1 ]; then
	if [ "$1" = "--aarch64" ]; then
		ARCH=aarch64
		TARBALL_ONLY=1
	elif [ "$1" = "--x86_64" ]; then
		ARCH=x86_64
		TARBALL_ONLY=1
	elif [ -d "$1" ]; then
		MOUNTS="$1"
	fi
else
	if [ "$(uname)" = "Linux" ]; then
		find_mountpoints_linux
	elif [ "$(uname)" = "Darwin" ]; then
		find_mountpoints_macos
	else
		echo "This script only supports auto-detection on Linux and MacOS."
		echo "Please specify the image root/mountpoint."
		echo "Or see the project README for manual install instructions."
		exit 1
	fi
fi

if [ "$TARBALL_ONLY" -ne 1 ] && ! check_fs ; then
	echo "Error: no valid image found at mountpoints (or manually provided path)"
	echo "If installing on a pi (sd card), please make sure it's freshly imaged with a custom hostname."
	echo "If the imager auto-ejected the disk, you may need to remove and reinsert it to make it visible again."
	echo "Alternately, re-run this script with either '--x86_64' or '--aarch64' options to create a portable package to extract manually,"\
	"or explicitly specify the root path (/) if you want to install to the live/running system."
	exit 1
fi

if [ "$TARBALL_ONLY" -ne 1 ]; then
	echo && echo
	if [ "$IS_PI" -eq 1 ]; then
		echo "A Raspberry Pi boot partition has been found mounted at $BOOTFS"
		echo "This script will modify firstrun.sh on that partition to install Viam agent."
	else
		echo "A systemd install was found installed in $ROOTFS"
		echo "Viam agent will be directly installed there."
	fi

	read -p "Continue pre-install? (y/n): " CONTINUE
	if [ "$CONTINUE" != "y" ]; then
		echo "Pre-install aborted."
		exit 1
	fi

	read -p "Path to custom viam-provisioning.json (leave empty to skip):" PROVISIONING_PATH 
fi

if ! create_tarball; then
	echo "Error creating preinstall package."
fi

if [ "$TARBALL_ONLY" -eq 1 ]; then
	echo && echo
	echo "Tarball package available at:"
	echo "$TARBALL"
	echo "Extract it manually with 'sudo tar -xJvpf $TARBALL -C <PATH_TO_ROOT_FS>'"
	exit 0
fi

if [ "$IS_PI" -eq "1" ]; then
	cp "$TARBALL" "$BOOTFS/viam-preinstall.tar.xz"
	if grep -q viam-preinstall.tar.xz "$BOOTFS/firstrun.sh"; then
		echo "It appears firstrun.sh has already been modified."
		echo "If you ran this script more than once WITHOUT booting the target SD card, then it should not cause issues."
		echo "If you did boot, you should make a fresh image before running this installer."
	else
		sed 's/rm -f \/boot\/firstrun.sh/tar -xJpf \/boot\/firmware\/viam-preinstall.tar.xz -C \/\nrm -f \/boot\/firstrun.sh/' "$BOOTFS/firstrun.sh" > "$BOOTFS/firstrun.sh.new" 
		mv "$BOOTFS/firstrun.sh.new" "$BOOTFS/firstrun.sh"
	fi
elif [ "$ROOTFS" != "" ]; then
	tar -xJpf "$TARBALL" -C "$ROOTFS"
else
	echo "Refusing to install to unknown/unset ROOTFS ($ROOTFS)"
fi

if [ "$TEMPDIR" != "" ]; then
	rm -rf "$TEMPDIR"
fi

sync
echo && echo
if [ "$ROOTFS" = "/" ]; then
	echo "Install complete! Reboot, or manually start the service with 'systemctl start viam-agent'"
else
	echo "Install complete! You can eject/unmount and boot the image now."
fi
