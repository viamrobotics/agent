package syscfg

import (
	"os"
	"testing"

	"go.viam.com/test"
)

func TestGenerateOrigins(t *testing.T) {
	t.Run("debian", func(t *testing.T) {
		contents, err := os.ReadFile("test-apt-policy-debian-bookworm.txt")
		test.That(t, err, test.ShouldBeNil)
		originsAll := generateOriginsInner(false, contents)
		test.That(t, originsAll, test.ShouldResemble, map[string]bool{
			`"origin=Debian,codename=bookworm";`:          true,
			`"origin=Debian,codename=bookworm-security";`: true,
			`"origin=Debian,codename=bookworm-updates";`:  true,
		})
		originsSecurity := generateOriginsInner(true, contents)
		test.That(t, originsSecurity, test.ShouldResemble, map[string]bool{
			`"origin=Debian,codename=bookworm-security";`: true,
		})
	})

	t.Run("ubuntu", func(t *testing.T) {
		t.Skip("todo: ubuntu parsing")
		contents, err := os.ReadFile("test-apt-policy-ubuntu-jammy.txt")
		test.That(t, err, test.ShouldBeNil)
		generateOriginsInner(false, contents)
		generateOriginsInner(true, contents)
	})
}
