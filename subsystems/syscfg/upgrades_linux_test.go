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
			`"origin=Debian,archive=stable";`:          true,
			`"origin=Debian,archive=stable-security";`: true,
			`"origin=Debian,archive=stable-updates";`:  true,
		})
		originsSecurity := generateOriginsInner(true, contents)
		test.That(t, originsSecurity, test.ShouldResemble, map[string]bool{
			`"origin=Debian,archive=stable-security";`: true,
		})
	})

	t.Run("ubuntu", func(t *testing.T) {
		contents, err := os.ReadFile("test-apt-policy-ubuntu-jammy.txt")
		test.That(t, err, test.ShouldBeNil)
		originsAll := generateOriginsInner(false, contents)
		test.That(t, originsAll, test.ShouldResemble, map[string]bool{
			`"origin=Ubuntu,archive=jammy";`:           true,
			`"origin=Ubuntu,archive=jammy-security";`:  true,
			`"origin=Ubuntu,archive=jammy-updates";`:   true,
			`"origin=Ubuntu,archive=jammy-backports";`: true,
		})
		originsSecurity := generateOriginsInner(true, contents)
		test.That(t, originsSecurity, test.ShouldResemble, map[string]bool{
			`"origin=Ubuntu,archive=jammy-security";`: true,
		})
	})
}
