package syscfg

import (
	"testing"

	"go.viam.com/test"
)

func TestParseWindowsUpdates(t *testing.T) {
	// With the progress stream silenced and stderr kept separate, the JSON is all
	// that reaches standard output.
	output := `[{"title":"2024-01 Cumulative Update for Windows 11 (KB5034123)",` +
		`"kb":"KB5034123","downloadSize":113246208,"size":"108MB",` +
		`"categories":["Security Updates","Windows 11"]},` +
		`{"title":"Intel driver update","kb":"","downloadSize":0,"size":"2.5MB","categories":["Drivers"]}]` +
		"\r\n"

	updates, err := parseWindowsUpdates(output)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, updates, test.ShouldResemble, []pendingUpdate{
		{
			// The title already carries the KB number, so it isn't prefixed again.
			Name:         "2024-01 Cumulative Update for Windows 11 (KB5034123)",
			DownloadSize: 113246208,
			Category:     "Security Updates/Windows 11",
		},
		{
			Name: "Intel driver update",
			// Older module versions don't surface MaxDownloadSize, so the preformatted
			// size is used instead.
			DownloadSize: 2621440,
			Category:     "Drivers",
		},
	})
}

func TestParseWindowsUpdatesKBPrefix(t *testing.T) {
	updates, err := parseWindowsUpdates(`[{"title":"Security Update for Windows","kb":"KB5034441"}]`)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, updates, test.ShouldResemble, []pendingUpdate{
		{Name: "KB5034441 Security Update for Windows"},
	})
}

func TestParseWindowsUpdatesEmpty(t *testing.T) {
	updates, err := parseWindowsUpdates("[]\r\n")
	test.That(t, err, test.ShouldBeNil)
	test.That(t, updates, test.ShouldBeEmpty)

	// Some PowerShell versions render an empty array as nothing at all.
	updates, err = parseWindowsUpdates("\r\n")
	test.That(t, err, test.ShouldBeNil)
	test.That(t, updates, test.ShouldBeEmpty)
}

func TestParseWindowsUpdatesNotJSON(t *testing.T) {
	// Anything else on standard output means the snippet didn't run as expected, which
	// is an error rather than "nothing was installed".
	_, err := parseWindowsUpdates("Get-WindowsUpdate : Access is denied\r\n")
	test.That(t, err, test.ShouldNotBeNil)
	test.That(t, err.Error(), test.ShouldContainSubstring, "Access is denied")
}
