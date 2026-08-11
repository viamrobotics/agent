package syscfg

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	errw "github.com/pkg/errors"
	"go.viam.com/rdk/logging"
)

const (
	// rpmQuerySeparator delimits repoquery fields. Package names, versions and
	// sizes never contain it, unlike whitespace which shows up in the human
	// readable sizes some dnf versions print.
	rpmQuerySeparator = "|"
	// dnfSizeQueryFormat asks dnf repoquery for the sizes check-update omits. Sizes
	// are printed as a byte count by some versions and as a human readable string by
	// others; [parseSize] accepts both.
	dnfSizeQueryFormat = "%{name}.%{arch}" + rpmQuerySeparator +
		"%{downloadsize}" + rpmQuerySeparator + "%{installsize}"
	// yumSizeQueryFormat is the same query for the classic repoquery binary, which
	// names the size tags differently than dnf does.
	yumSizeQueryFormat = "%{name}.%{arch}" + rpmQuerySeparator +
		"%{packagesize}" + rpmQuerySeparator + "%{installedsize}"
	// dnf5SizeQueryFormat is [dnfSizeQueryFormat] for dnf5, which stopped printing a
	// newline after each record and instead expects the format to ask for one with
	// an escape sequence. Only dnf5 gets it: dnf4 already separates records itself,
	// and isn't documented to interpret the escape.
	dnf5SizeQueryFormat = dnfSizeQueryFormat + `\n`
)

type rpmPackageManager struct {
	logger logging.Logger
	useDnf bool
	// dnf5 reports that the dnf binary is dnf5 (Fedora 41+), which is a rewrite
	// with its own command line quirks, rather than dnf4.
	dnf5 bool
}

// String implements [packageManager].
func (r rpmPackageManager) String() string {
	manager := "yum"
	switch {
	case r.dnf5:
		manager = "dnf5"
	case r.useDnf:
		manager = "dnf"
	}
	return fmt.Sprintf("rpm(%s)", manager)
}

// isDnf5 reports whether the installed dnf binary is dnf5. `dnf --version`
// prints "dnf5 version 5.x.y" on dnf5 and a bare "4.x.y" on dnf4, so the first
// integer to appear is the major version either way. When the version can't be
// determined, assume dnf4, whose behavior this code has relied on the longest.
func isDnf5(ctx context.Context, logger logging.Logger) bool {
	output, err := exec.CommandContext(ctx, "dnf", "--version").Output()
	if err != nil {
		logger.Debugw("Could not determine dnf version, assuming dnf4", "err", err)
		return false
	}
	return dnfMajorVersion(string(output)) >= 5
}

var dnfVersionRegex = regexp.MustCompile(`\d+`)

// dnfMajorVersion extracts the major version from `dnf --version` output,
// returning 0 when there is none to find.
func dnfMajorVersion(output string) int {
	major, err := strconv.Atoi(dnfVersionRegex.FindString(output))
	if err != nil {
		return 0
	}
	return major
}

func (r rpmPackageManager) needsReboot(ctx context.Context) bool {
	if err := r.ensureNeedsRestarting(ctx); err != nil {
		r.logger.Errorw(
			"Could not verify needs-restarting installation to check for reboot status",
			"err", err,
		)
		return false
	}
	// needs-restarting -r exits 1 when a reboot is required, 0 otherwise.
	// Any other non-zero exit is treated as "not required".
	cmd := exec.CommandContext(ctx, "needs-restarting", "-r")
	if err := cmd.Run(); err != nil {
		if err, ok := errors.AsType[*exec.ExitError](err); ok {
			return err.ExitCode() == 1
		}
	}
	return false
}

// lockPaths implements [packageManager]. rpm's %_rpmlock_path, held across
// rpmtsRun, so it covers dnf and yum alike. The rpm 4.16 (RHEL 9) switch from
// Berkeley DB to sqlite moved package data, not this lock: verified held during a
// dnf transaction on 4.14 (RHEL 8) and present on 4.11 (RHEL 7).
func (r rpmPackageManager) lockPaths() []string {
	return []string{"/var/lib/rpm/.rpm.lock"}
}

func (r rpmPackageManager) getProgram() string {
	program := "yum"
	if r.useDnf {
		program = "dnf"
	}
	return program
}

func (r rpmPackageManager) ensureNeedsRestarting(ctx context.Context) error {
	if _, err := exec.LookPath("needs-restarting"); err == nil {
		return nil
	}
	return pkgCmd(ctx, r.logger, r.getProgram(), "install", "-y", "yum-utils")
}

// prepare implements [packageManager].
func (r rpmPackageManager) prepare(ctx context.Context, securityOnly bool) error {
	if err := r.ensureNeedsRestarting(ctx); err != nil {
		return errw.Wrap(err, "failed to locate or install needs-restarting")
	}
	// check-update refreshes expired metadata itself, so there is nothing else to
	// do here.
	return nil
}

// pendingUpgrades implements [packageManager].
//
// The columnar text output of check-update is parsed rather than dnf5's --json,
// because dnf4 (RHEL 8 and 9) and yum have no JSON support and this path has to
// work everywhere. check-update reports no sizes, so those are looked up
// separately. Category is only known when we asked for security updates, since
// check-update doesn't report per-package advisory types.
func (r rpmPackageManager) pendingUpgrades(ctx context.Context, securityOnly bool) ([]pendingUpdate, error) {
	args := []string{"check-update", "-q"}
	if securityOnly {
		args = append(args, "--security")
	}
	//nolint: gosec
	cmd := exec.CommandContext(ctx, r.getProgram(), args...)
	// check-update exits 100 when updates are available and 0 when there are none;
	// anything else is a real failure.
	output, err := cmd.Output()
	if err != nil {
		exitErr, ok := errors.AsType[*exec.ExitError](err)
		if !ok {
			return nil, errw.Wrapf(err, "%s %v", r.getProgram(), args)
		}
		if exitErr.ExitCode() != 100 {
			return nil, errw.Wrapf(err, "%s %v: %s", r.getProgram(), args, exitErr.Stderr)
		}
	}

	updates := parseRPMCheckUpdate(string(output))
	r.fillPackageSizes(ctx, updates)
	return updates, nil
}

// fillPackageSizes looks up the download and installed sizes of the passed updates,
// which check-update doesn't report. repoquery isn't available on every
// distribution and its query tags have varied across versions, so a failed lookup
// is logged and leaves the sizes unknown rather than failing the upgrade.
func (r rpmPackageManager) fillPackageSizes(ctx context.Context, updates []pendingUpdate) {
	if len(updates) == 0 {
		return
	}

	output, err := r.sizeQueryCommand(ctx).Output()
	if err != nil {
		r.logger.Debugw("Could not read pending update sizes from repoquery",
			"package_manager", r.String(), "err", err)
		return
	}

	sizes := parseRPMSizes(string(output))
	for i, update := range updates {
		if size, ok := sizes[update.Name]; ok {
			updates[i].DownloadSize = size.DownloadSize
			updates[i].InstalledSize = size.InstalledSize
		}
	}
}

// sizeQueryCommand returns the command that reports the sizes of every pending
// upgrade. With dnf, repoquery is a subcommand; on yum systems it is a
// standalone binary shipped in yum-utils.
func (r rpmPackageManager) sizeQueryCommand(ctx context.Context) *exec.Cmd {
	if r.useDnf {
		format := dnfSizeQueryFormat
		if r.dnf5 {
			format = dnf5SizeQueryFormat
		}
		return exec.CommandContext(ctx, "dnf", "repoquery", "-q", "--upgrades",
			"--queryformat", format)
	}
	// --all matches every package, which --pkgnarrow=updates then narrows to the
	// pending updates, like dnf's --upgrades. -q is accepted (and ignored) for rpm
	// compatibility.
	return exec.CommandContext(ctx, "repoquery", "-q", "--all", "--pkgnarrow=updates",
		"--queryformat", yumSizeQueryFormat)
}

// runUpgrade implements [packageManager]. The returned packages are parsed from
// the transaction output even when the upgrade fails, since a package reported
// there was installed before the transaction died.
func (r rpmPackageManager) runUpgrade(ctx context.Context, securityOnly bool) ([]pendingUpdate, error) {
	args := []string{"upgrade", "-y"}
	if securityOnly {
		args = append(args, "--security")
	}
	output, err := pkgCmdOutput(ctx, r.logger, r.getProgram(), args...)
	return parseRPMUpgradeOutput(output), err
}

// parseRPMCheckUpdate extracts the packages to be installed from the output of
// `dnf check-update -q`, whose upgradable packages are listed one per line as
// "<name>.<arch>  <version>  <repo>". No category is recorded because
// check-update doesn't report per-package advisory types.
func parseRPMCheckUpdate(output string) []pendingUpdate {
	var updates []pendingUpdate
	for _, line := range strings.Split(output, "\n") {
		// The trailing "Obsoleting Packages" section repeats packages already listed
		// above, alongside the installed packages they obsolete.
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		fields := strings.Fields(line)
		// Skip blank lines and the "Security: ... is an installed security update"
		// notes yum appends.
		if len(fields) != 3 || strings.HasSuffix(fields[0], ":") {
			continue
		}
		updates = append(updates, pendingUpdate{
			Name:    fields[0],
			Version: fields[1],
		})
	}
	return updates
}

// rpmInstalledSections are the summary headings under which dnf4 and yum list
// what a completed transaction installed, one heading per transaction verb.
// Removal headings ("Removed:", "Erased:", "Replaced:") are deliberately absent:
// those packages left the system rather than landing on it.
var rpmInstalledSections = []string{
	"Installed:", "Upgraded:", "Updated:", "Downgraded:", "Reinstalled:",
	"Dependency Installed:", "Dependency Updated:",
}

// dnf5ProgressRegex matches the "[3/7] Upgrading <name-version.arch> ..."
// per-package progress lines dnf5 prints while running the transaction, the only
// place dnf5's output reports individual packages as installed. The verb keeps
// non-package steps ("Verify package files", "Prepare transaction") and the
// verb-less download progress lines from matching.
var dnf5ProgressRegex = regexp.MustCompile(`^\[\d+/\d+\] (?:Installing|Upgrading|Downgrading|Reinstalling) (\S+)`)

// parseRPMUpgradeOutput extracts the packages a `dnf/yum upgrade -y` run actually
// installed from its output, in the "<name>.<arch>"/version form check-update
// lists pending updates in. Anything unrecognized parses to nothing, and the
// result log omits the package list.
func parseRPMUpgradeOutput(output string) []pendingUpdate {
	var updates []pendingUpdate
	seen := map[string]bool{}
	add := func(update pendingUpdate) {
		if !seen[update.Name] {
			seen[update.Name] = true
			updates = append(updates, update)
		}
	}

	inSection := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		if match := dnf5ProgressRegex.FindStringSubmatch(trimmed); match != nil {
			if update, ok := parseRPMFullName(match[1]); ok {
				add(update)
			}
			continue
		}

		// Section headings sit flush left; the packages under them are indented.
		if !strings.HasPrefix(line, " ") {
			inSection = slices.Contains(rpmInstalledSections, trimmed)
			continue
		}
		if !inSection {
			continue
		}

		// Sections list several packages per line, columnar. dnf4 prints each as a
		// single "name-version-release.arch" token; yum splits the same package into
		// a "name.arch epoch:version-release" pair.
		fields := strings.Fields(trimmed)
		for i := 0; i < len(fields); i++ {
			if update, ok := parseRPMFullName(fields[i]); ok {
				add(update)
				continue
			}
			if i+1 < len(fields) && strings.Contains(fields[i], ".") && startsWithDigit(fields[i+1]) {
				add(pendingUpdate{Name: fields[i], Version: fields[i+1]})
				i++
			}
		}
	}
	return updates
}

// parseRPMFullName splits a full package spec like
// "openssl-libs-1:3.2.2-3.fc40.x86_64" into the "<name>.<arch>" and version
// forms check-update uses, so installed packages line up with the pending list
// by name. Reports false for anything not shaped like name-version-release.arch,
// including the "name.arch" half of a yum package pair.
func parseRPMFullName(spec string) (pendingUpdate, bool) {
	archIdx := strings.LastIndex(spec, ".")
	if archIdx < 0 {
		return pendingUpdate{}, false
	}
	nvr, arch := spec[:archIdx], spec[archIdx+1:]

	relIdx := strings.LastIndex(nvr, "-")
	if relIdx < 0 {
		return pendingUpdate{}, false
	}
	verIdx := strings.LastIndex(nvr[:relIdx], "-")
	if verIdx < 0 {
		return pendingUpdate{}, false
	}

	name, version, release := nvr[:verIdx], nvr[verIdx+1:relIdx], nvr[relIdx+1:]
	// Versions and releases start with a digit (the version possibly behind an
	// "epoch:" prefix, itself numeric), unlike the dash-separated words of a
	// package name. This keeps a bare name like "java-1.8.0-openjdk.x86_64" from
	// being misread as name "java" version "1.8.0-openjdk".
	if name == "" || arch == "" || !startsWithDigit(version) || !startsWithDigit(release) {
		return pendingUpdate{}, false
	}
	return pendingUpdate{Name: name + "." + arch, Version: version + "-" + release}, true
}

// startsWithDigit reports whether s begins with an ASCII digit, the shape of rpm
// versions and releases (an "epoch:" prefix included, epochs being numeric).
func startsWithDigit(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

// parseRPMSizes extracts package sizes from repoquery output in
// [dnfSizeQueryFormat] or [yumSizeQueryFormat], keyed by the "<name>.<arch>" that
// check-update lists.
func parseRPMSizes(output string) map[string]pendingUpdate {
	sizes := map[string]pendingUpdate{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), rpmQuerySeparator)
		if len(fields) != 3 {
			continue
		}
		sizes[fields[0]] = pendingUpdate{
			DownloadSize:  parseSize(fields[1]),
			InstalledSize: parseSize(fields[2]),
		}
	}
	return sizes
}
