package syscfg

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

// A reboot must never be reported while an upgrade is installing, even once one
// is known to be pending: rebooting mid-transaction breaks the package database.
func TestNeedsOSRebootWaitsForUpgradeToFinish(t *testing.T) {
	withPackageLocks(t)

	newSubsystem := func() *Subsystem {
		return &Subsystem{
			logger: logging.NewTestLogger(t),
			cfg: utils.SystemConfiguration{
				OSAutoUpgradeType: utils.OSAutoUpgradeManagedSecurity,
			},
		}
	}

	t.Run("pending reboot is reported when idle", func(t *testing.T) {
		s := newSubsystem()
		s.needsOSReboot = true
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeTrue)
	})

	t.Run("pending reboot is suppressed while upgrading", func(t *testing.T) {
		s := newSubsystem()
		s.needsOSReboot = true
		defer s.upgrade.begin()()
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeFalse)
	})

	t.Run("reboot is reported again once the upgrade finishes", func(t *testing.T) {
		s := newSubsystem()
		s.needsOSReboot = true
		done := s.upgrade.begin()
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeFalse)
		done()
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeTrue)
	})

	// The in-process flag above only covers upgrades this agent runs. A package
	// transaction started by anything else must hold the reboot back too.
	t.Run("pending reboot is suppressed by an external package transaction", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lock")
		f, err := os.Create(path)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, f.Close(), test.ShouldBeNil)

		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperHoldsPackageLock$")
		cmd.Env = append(os.Environ(), lockHelperPathEnv+"="+path)
		stdin, err := cmd.StdinPipe()
		test.That(t, err, test.ShouldBeNil)
		stdout, err := cmd.StdoutPipe()
		test.That(t, err, test.ShouldBeNil)
		test.That(t, cmd.Start(), test.ShouldBeNil)
		defer func() {
			stdin.Close()
			cmd.Wait()
		}()

		var locked bool
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "locked" {
				locked = true
				break
			}
		}
		test.That(t, locked, test.ShouldBeTrue)

		withPackageLocks(t, path)

		s := newSubsystem()
		s.needsOSReboot = true
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeFalse)

		// Releasing the lock unblocks the reboot.
		stdin.Close()
		test.That(t, cmd.Wait(), test.ShouldBeNil)
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeTrue)
	})
}

func TestParseAptSimulateUpgrade(t *testing.T) {
	output := `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages will be upgraded:
  libc6 openssl
2 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Inst libc6 [2.36-9+deb12u7] (2.36-9+deb12u10 Debian:12.9/stable [arm64])
Conf libc6 (2.36-9+deb12u10 Debian:12.9/stable [arm64])
Inst openssl [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [arm64])
Inst linux-image-6.1.0-30-arm64 (6.1.124-1 Debian:12.9/stable [arm64])
Conf openssl (3.0.15-1~deb12u1 Debian-Security:12/stable-security [arm64])
`
	test.That(t, parseAptSimulateUpgrade(output), test.ShouldResemble, []pendingUpdate{
		{Name: "libc6", CurrentVersion: "2.36-9+deb12u7", Version: "2.36-9+deb12u10"},
		{
			Name: "openssl", CurrentVersion: "3.0.11-1~deb12u2", Version: "3.0.15-1~deb12u1",
			Category: "security",
		},
		{Name: "linux-image-6.1.0-30-arm64", Version: "6.1.124-1"},
	})

	test.That(t, parseAptSimulateUpgrade("0 upgraded, 0 newly installed, 0 to remove.\n"), test.ShouldBeNil)
}

func TestParseAptCacheSizes(t *testing.T) {
	output := `Package: libc6
Source: glibc
Version: 2.36-9+deb12u10
Installed-Size: 12759
Depends: libgcc-s1
Description-en: GNU C Library
Size: 2799652
MD5sum: 0123456789abcdef0123456789abcdef

Package: openssl
Version: 3.0.15-1~deb12u1
Installed-Size: 1520
Size: 1414000

`
	sizes := parseAptCacheSizes(output)
	test.That(t, sizes, test.ShouldResemble, map[string]pendingUpdate{
		"libc6=2.36-9+deb12u10": {DownloadSize: 2799652, InstalledSize: 12759 * 1024},
		"openssl=3.0.15-1~deb12u1": {
			DownloadSize: 1414000, InstalledSize: 1520 * 1024,
		},
	})

	test.That(t, parseAptCacheSizes(""), test.ShouldBeEmpty)
}

func TestParseUnattendedUpgradeDryRun(t *testing.T) {
	output := `Starting unattended upgrades script
Allowed origins are: origin=Debian,codename=bookworm-security
Checking: libc6 ([<Origin component:'main' archive:'stable-security'>])
Packages that will be upgraded: libc6 openssl
Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
`
	test.That(t, parseUnattendedUpgradeDryRun(output), test.ShouldResemble, []string{"libc6", "openssl"})

	noUpdates := "No packages found that can be upgraded unattended and no pending auto-removals\n"
	test.That(t, parseUnattendedUpgradeDryRun(noUpdates), test.ShouldBeNil)
}

func TestRestrictToNames(t *testing.T) {
	candidates := []pendingUpdate{
		{Name: "libc6", CurrentVersion: "2.36-9+deb12u7", Version: "2.36-9+deb12u10"},
		{Name: "openssl", Version: "3.0.15-1~deb12u1", Category: "security"},
	}

	// "held-back" isn't in the simulated upgrade, but unattended-upgrade still
	// intends to install it, so it must survive as a name-only entry.
	updates := restrictToNames(candidates, []string{"openssl", "held-back"})
	test.That(t, updates, test.ShouldResemble, []pendingUpdate{
		{Name: "openssl", Version: "3.0.15-1~deb12u1", Category: "security"},
		{Name: "held-back", Category: "security"},
	})

	test.That(t, restrictToNames(candidates, nil), test.ShouldBeEmpty)
}

func TestParseRPMCheckUpdate(t *testing.T) {
	output := `
kernel.x86_64                      6.11.4-201.fc40         updates
openssl-libs.x86_64                1:3.2.2-3.fc40          updates
Security: kernel-6.11.4-201.fc40.x86_64 is an installed security update

Obsoleting Packages
new-pkg.noarch                     2.0-1.fc40              updates
    old-pkg.noarch                 1.0-1.fc40              @System
`
	test.That(t, parseRPMCheckUpdate(output), test.ShouldResemble, []pendingUpdate{
		{Name: "kernel.x86_64", Version: "6.11.4-201.fc40", Category: "security"},
		{Name: "openssl-libs.x86_64", Version: "1:3.2.2-3.fc40", Category: "security"},
	})

	test.That(t, parseRPMCheckUpdate(""), test.ShouldBeNil)
}

func TestRPMSizeQueryCommand(t *testing.T) {
	dnf := rpmPackageManager{useDnf: true}
	test.That(t, dnf.sizeQueryCommand(t.Context()).Args, test.ShouldResemble, []string{
		"dnf", "repoquery", "-q", "--upgrades", "--queryformat", dnfSizeQueryFormat,
	})

	// dnf5 stopped printing a newline after each record, so its format has to ask
	// for one explicitly.
	dnf5 := rpmPackageManager{useDnf: true, dnf5: true}
	test.That(t, dnf5.sizeQueryCommand(t.Context()).Args, test.ShouldResemble, []string{
		"dnf", "repoquery", "-q", "--upgrades", "--queryformat", dnfSizeQueryFormat + `\n`,
	})

	// On yum systems repoquery is a standalone binary, not a yum subcommand.
	yum := rpmPackageManager{useDnf: false}
	test.That(t, yum.sizeQueryCommand(t.Context()).Args, test.ShouldResemble, []string{
		"repoquery", "-q", "--all", "--pkgnarrow=updates", "--queryformat", yumSizeQueryFormat,
	})
}

func TestDnfMajorVersion(t *testing.T) {
	dnf4Output := `4.14.0
  Installed: dnf-0:4.14.0-1.fc38.noarch at Thu 06 Apr 2023 12:00:00 AM UTC
  Built    : Fedora Project at Wed 15 Feb 2023 12:00:00 AM UTC
`
	test.That(t, dnfMajorVersion(dnf4Output), test.ShouldEqual, 4)

	dnf5Output := "dnf5 version 5.2.6.2\n"
	test.That(t, dnfMajorVersion(dnf5Output), test.ShouldEqual, 5)

	test.That(t, dnfMajorVersion(""), test.ShouldEqual, 0)
	test.That(t, dnfMajorVersion("command not found"), test.ShouldEqual, 0)
}

func TestParseRPMSizes(t *testing.T) {
	// dnf versions differ on whether sizes are byte counts or human readable.
	output := `kernel.x86_64|2799652|48234496
openssl-libs.x86_64|1.4 M|7.8 M
malformed-line-without-separator
`
	test.That(t, parseRPMSizes(output), test.ShouldResemble, map[string]pendingUpdate{
		"kernel.x86_64":       {DownloadSize: 2799652, InstalledSize: 48234496},
		"openssl-libs.x86_64": {DownloadSize: 1468006, InstalledSize: 8178892},
	})
}
