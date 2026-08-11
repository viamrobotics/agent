package syscfg

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const rebootRequiredPath = "/var/run/reboot-required"

// aptInstLineRegex matches the "Inst <name> [<installed version>] (<candidate
// version> <origins> [<arch>])" lines emitted by `apt-get --simulate upgrade`. The
// installed version is absent for packages being newly installed.
var aptInstLineRegex = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]*)\])? \(([^)]*)\)`)

// unattendedDryRunPrefix is the line unattended-upgrade --dry-run prints listing
// the packages it would install.
const unattendedDryRunPrefix = "Packages that will be upgraded:"

type aptPackageManager struct {
	logger logging.Logger
}

// String implements [packageManager].
func (a aptPackageManager) String() string {
	return "apt"
}

func (a aptPackageManager) needsReboot(ctx context.Context) bool {
	_, err := os.Stat(rebootRequiredPath)
	return err == nil
}

// lockPaths implements [packageManager]. lock-frontend is held across the whole
// transaction including the dpkg calls apt spawns, making it the broader of the two.
func (a aptPackageManager) lockPaths() []string {
	return []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}
}

// prepare implements [packageManager].
func (a aptPackageManager) prepare(ctx context.Context, securityOnly bool) error {
	// Refresh package lists.
	if err := pkgCmd(ctx, a.logger, "apt-get", "update"); err != nil {
		return err
	}

	// unattended-upgrades handles creating /var/run/reboot-required.
	if err := a.ensureUnattendedUpgrades(ctx); err != nil {
		return err
	}

	if securityOnly {
		// Both the dry run that lists pending upgrades and the real upgrade read this
		// config, so write it before either of them runs.
		return a.writeSecurityOrigins(ctx)
	}
	return nil
}

// pendingUpgrades implements [packageManager].
//
// Names, versions and the origin the package comes from are read from a simulated
// upgrade; sizes come from the package cache, since the simulation only reports
// totals. apt has no update classification beyond the source archive, so Category
// is "security" for packages coming from a security archive and empty otherwise.
func (a aptPackageManager) pendingUpgrades(ctx context.Context, securityOnly bool) ([]pendingUpdate, error) {
	candidates, err := a.simulateUpgrade(ctx)
	if err != nil {
		if !securityOnly {
			return nil, err
		}
		// In security mode the simulation only adds detail to the list below, so carry
		// on without it.
		a.logger.Debugw("Could not simulate apt upgrade for pending update detail", "err", err)
	}

	updates := candidates
	if securityOnly {
		// unattended-upgrade, not apt-get, decides what a security upgrade installs, so
		// it has the authoritative list. It reports names only, so pair them up with
		// the detail from the simulation.
		dryRun, err := a.unattendedUpgrade(ctx, "--dry-run")
		if err != nil {
			return nil, err
		}
		updates = restrictToNames(candidates, parseUnattendedUpgradeDryRun(string(dryRun)))
	}

	a.fillPackageSizes(ctx, updates)
	return updates, nil
}

// simulateUpgrade lists the packages a full upgrade would install, without
// installing anything.
func (a aptPackageManager) simulateUpgrade(ctx context.Context) ([]pendingUpdate, error) {
	cmd := exec.CommandContext(ctx, "apt-get", "--simulate", "upgrade")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := cmd.Output()
	if err != nil {
		return nil, errw.Wrap(err, "simulating apt-get upgrade")
	}
	return parseAptSimulateUpgrade(string(output)), nil
}

// restrictToNames returns the passed names as updates, in the order given,
// reusing the detail from candidates for the names found there. Names with no
// matching candidate still get an entry, so an upgrade the simulation held
// back is logged rather than silently dropped.
func restrictToNames(candidates []pendingUpdate, names []string) []pendingUpdate {
	byName := make(map[string]pendingUpdate, len(candidates))
	for _, candidate := range candidates {
		byName[candidate.Name] = candidate
	}

	updates := make([]pendingUpdate, 0, len(names))
	for _, name := range names {
		update, ok := byName[name]
		if !ok {
			update = pendingUpdate{Name: name}
		}
		updates = append(updates, update)
	}
	return updates
}

// fillPackageSizes looks up the download and installed sizes of the passed
// updates, which a simulated upgrade reports only as totals. Sizes are a logging
// nicety, so a lookup failure is logged and left as an unknown size rather than
// failing the upgrade.
func (a aptPackageManager) fillPackageSizes(ctx context.Context, updates []pendingUpdate) {
	specs := make([]string, 0, len(updates))
	for _, update := range updates {
		if update.Version != "" {
			specs = append(specs, update.Name+"="+update.Version)
		}
	}
	if len(specs) == 0 {
		return
	}

	//nolint: gosec
	cmd := exec.CommandContext(ctx, "apt-cache", append([]string{"show"}, specs...)...)
	output, err := cmd.Output()
	if err != nil {
		a.logger.Debugw("Could not read pending update sizes from apt-cache", "err", err)
		return
	}

	sizes := parseAptCacheSizes(string(output))
	for i, update := range updates {
		if size, ok := sizes[update.Name+"="+update.Version]; ok {
			updates[i].DownloadSize = size.DownloadSize
			updates[i].InstalledSize = size.InstalledSize
		}
	}
}

func (a aptPackageManager) runUpgrade(ctx context.Context, securityOnly bool) error {
	if securityOnly {
		return a.runSecurityUpgrade(ctx)
	}
	return a.runFullUpgrade(ctx)
}

func (a aptPackageManager) runFullUpgrade(ctx context.Context) error {
	return pkgCmd(ctx, a.logger, "apt-get", "upgrade", "-y",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
	)
}

func (a aptPackageManager) ensureUnattendedUpgrades(ctx context.Context) error {
	if err := verifyUnattendedUpgrade(ctx); err != nil {
		a.logger.Infow("Installing unattended-upgrades package", "reason", err)
		if installErr := doInstall(ctx); installErr != nil {
			return errw.Wrap(installErr, "installing unattended-upgrades package")
		}
		// The package enables a systemd timer on first install. Disable it to be
		// safe.
		return setTimer(ctx, false)
	}
	return nil
}

// writeSecurityOrigins scopes unattended-upgrade to the security repos only.
func (a aptPackageManager) writeSecurityOrigins(ctx context.Context) error {
	confContents, err := generateOrigins(ctx, true)
	if err != nil {
		return errw.Wrap(err, "generating security origins")
	}

	isNew, err := utils.WriteFileIfNew(unattendedUpgradesPath, []byte(confContents))
	if err != nil {
		return errw.Wrap(err, "writing unattended-upgrades config")
	}
	if isNew {
		a.logger.Infow("Wrote security-only unattended-upgrades config",
			"path", unattendedUpgradesPath, "contents", confContents)
	}
	return nil
}

func (a aptPackageManager) runSecurityUpgrade(ctx context.Context) error {
	_, err := a.unattendedUpgrade(ctx)
	return err
}

// unattendedUpgrade runs the unattended-upgrade binary, returning its combined
// output. Pass --dry-run to list what would be installed without installing it.
func (a aptPackageManager) unattendedUpgrade(ctx context.Context, extraArgs ...string) ([]byte, error) {
	args := append([]string{"--verbose"}, extraArgs...)
	//nolint: gosec
	cmd := exec.CommandContext(ctx, "unattended-upgrade", args...)
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, errw.Wrapf(err, "unattended-upgrade %v: %s", args, output)
	}
	a.logger.Debugw("unattended-upgrade succeeded", "args", args, "output", string(output))
	return output, nil
}

// parseAptSimulateUpgrade extracts the packages to be installed from the output of
// `apt-get --simulate upgrade`, which reports no sizes.
func parseAptSimulateUpgrade(output string) []pendingUpdate {
	var updates []pendingUpdate
	for _, line := range strings.Split(output, "\n") {
		match := aptInstLineRegex.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		// The parenthesized detail is "<candidate version> <origins...> [<arch>]".
		detail := strings.Fields(match[3])
		if len(detail) == 0 {
			continue
		}
		updates = append(updates, pendingUpdate{
			Name:           match[1],
			CurrentVersion: match[2],
			Version:        detail[0],
			Category:       aptCategory(strings.Join(detail[1:], " ")),
		})
	}
	return updates
}

// aptCategory classifies an update by the origins it is available from, the only
// classification apt exposes. Origins look like
// "Debian-Security:12/stable-security" or "Debian:12.9/stable".
func aptCategory(origins string) string {
	if strings.Contains(strings.ToLower(origins), categorySecurity) {
		return categorySecurity
	}
	return ""
}

// parseAptCacheSizes extracts package sizes from `apt-cache show` output, keyed by
// the "<name>=<version>" spec that selects that exact package.
func parseAptCacheSizes(output string) map[string]pendingUpdate {
	sizes := map[string]pendingUpdate{}
	// Stanzas, one per package version, are separated by a blank line.
	for _, stanza := range strings.Split(output, "\n\n") {
		var name, version string
		var update pendingUpdate
		for _, line := range strings.Split(stanza, "\n") {
			field, value, found := strings.Cut(line, ": ")
			if !found {
				continue
			}
			value = strings.TrimSpace(value)
			switch field {
			case "Package":
				name = value
			case "Version":
				version = value
			case "Size":
				update.DownloadSize = parseSize(value)
			case "Installed-Size":
				// Unlike Size, which is in bytes, Installed-Size is in kibibytes.
				update.InstalledSize = parseSize(value) * 1024
			}
		}
		if name != "" && version != "" {
			sizes[name+"="+version] = update
		}
	}
	return sizes
}

// parseUnattendedUpgradeDryRun extracts package names from the output of
// `unattended-upgrade --verbose --dry-run`. Versions aren't reported, so this is
// names only.
func parseUnattendedUpgradeDryRun(output string) []string {
	var updates []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, unattendedDryRunPrefix) {
			continue
		}
		updates = append(updates, strings.Fields(strings.TrimPrefix(line, unattendedDryRunPrefix))...)
	}
	return updates
}
