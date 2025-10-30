package utils

import (
	"testing"

	"go.uber.org/zap/zapcore"
	"go.viam.com/rdk/logging"
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

func TestUnstructuredLogger(t *testing.T) {
	// We want to test the `MatchingLogger`. A `MatchingLogger` takes bytes (of raw log lines) and
	// outputs those bytes:
	// - Wrapped in a LogEntry envelop and written to the underlying logger if stderr or
	// - Directly to syslog if stdout
	//
	// We set up an "observed" test logger to capture which logs get written to it.
	logger, observedLogs := logging.NewObservedTestLogger(t)

	// Setting up a stdout logger
	StdOutLogger := NewMatchingLogger(logger, true, "viam-server.StdOut")

	// Write a normal log line from stdout, should not relog.
	StdOutLogger.Write([]byte("2025-06-27T01:59:16.710Z	INFO	rdk	config/logging_level.go:38	Log\n"))
	test.That(t, len(observedLogs.TakeAll()), test.ShouldEqual, 0)

	// Setting up a stderr logger
	StdErrLogger := NewMatchingLogger(logger, false, "viam-server.StdErr")

	// Write a normal log line from stderr, should relog once per log, so twice total.
	StdErrLogger.Write([]byte(`2025-06-27T01:59:16.710Z	INFO	rdk	config/logging_level.go:38	Log 
	Candidate pair bandwidth log. Agent: 0x40018f0308 From: 127.0.0.1:51248 To:`))
	test.That(t, len(observedLogs.TakeAll()), test.ShouldEqual, 2)
}
