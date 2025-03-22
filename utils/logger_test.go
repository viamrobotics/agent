package utils

import (
	"testing"

	"go.uber.org/zap/zapcore"
	"go.viam.com/test"
)

func TestStripAnsiColorCodes(t *testing.T) {
	test.That(t, stripAnsiColorCodes([]byte("\x1b[34mINFO\x1b[0m")), test.ShouldResemble, []byte("INFO"))
}

func TestParseLog(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tail := "message message message"
		parsed := parseLog([]byte("20240601T00:00:00\tINFO\tparsetest\tfile.go:10\t" + tail))
		test.That(t, parsed.valid(), test.ShouldBeTrue)
		test.That(t, parsed.tail, test.ShouldResemble, []byte(tail))
		entry := parsed.entry()
		test.That(t, entry.Message, test.ShouldResemble, tail)
		test.That(t, entry.LoggerName, test.ShouldResemble, "parsetest")
		test.That(t, entry.Level, test.ShouldResemble, zapcore.InfoLevel)
		test.That(t, entry.Caller.File, test.ShouldResemble, "file.go")
		test.That(t, entry.Caller.Line, test.ShouldResemble, 10)
	})

	// this tests the fallback case to make sure we don't lose logs that are unparseable.
	t.Run("invalid", func(t *testing.T) {
		line := "I am hard to parse probably, I don't have any tabs"
		parsed := parseLog([]byte(line))
		test.That(t, parsed.valid(), test.ShouldBeTrue)
		test.That(t, parsed.tail, test.ShouldResemble, []byte(line))
		entry := parsed.entry()
		test.That(t, entry.Message, test.ShouldResemble, line)
	})

	// this makes sure a completely malformed log + a log error won't result in a crash.
	t.Run("entry-doesnt-crash", func(t *testing.T) {
		parsed := &parsedLog{}
		entry := parsed.entry()
		test.That(t, entry.Message, test.ShouldResemble, "")
	})
}
