package agent

import (
	"testing"

	"go.viam.com/test"
)

func TestStripAnsiColorCodes(t *testing.T) {
	test.That(t, stripAnsiColorCodes([]byte("\x1b[34mINFO\x1b[0m")), test.ShouldResemble, []byte("INFO"))
}
