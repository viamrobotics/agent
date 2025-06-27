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
	// - Wrapped in a LogEntry envelop and written to the underlying logger or
	// - Directly to stdout
	//
	// We set up an "observed" test logger to capture which logs get written to it.
	logger, observedLogs := logging.NewObservedTestLogger(t)
	// We use `false, false` such that "unstructured" logs:
	// - are logged as warns (unimportant here)
	// - And that "structured" logs are _not_ written to the underlying logger.
	//
	// Where "structured" logs are identified by starting with a `<YYYY>-<MM>-<DD>T` pattern.
	matchingLogger := NewMatchingLogger(logger, false, false, "viam-server.StdOut")

	// Write a normal structured log line to the `matchingLogger`. This will not be forwarded to the
	// underlying observed logger.
	matchingLogger.Write([]byte("2025-06-27T01:59:16.710Z	INFO	rdk	config/logging_level.go:38	Log\n"))
	test.That(t, len(observedLogs.TakeAll()), test.ShouldEqual, 0)

	// Write an unstructured log line. This is perhaps something that writes directly to the
	// viam-server stdout without the help of a viam configured logger. Assert this log line is
	// written to the underlying logger.
	matchingLogger.Write([]byte("Candidate pair bandwidth log. Agent: 0x40018f0308 From: 127.0.0.1:51248 To:\n"))
	test.That(t, len(observedLogs.TakeAll()), test.ShouldEqual, 1)

	// As a `MatchingLogger` is attached directly to a process' stdout, there's no guarantee
	// `MatchingLogger.Write([]byte)` is called exactly once per log line. Feed four log lines. Two
	// "structured" and two "unstructured". Assert only two get forwarded to the underlying logger.
	matchingLogger.Write([]byte(`2025-06-27T01:59:16.710Z	INFO	rdk	config/logging_level.go:38	Log
Candidate pair bandwidth log. Agent: 0x40018f0308 From: 127.0.0.1:51248 To:
2025-06-27T01:59:16.710Z	INFO	rdk	config/logging_level.go:38	Log
Candidate pair bandwidth log. Agent: 0x40018f0308 From: 127.0.0.1:51248 To:
`))
	test.That(t, len(observedLogs.TakeAll()), test.ShouldEqual, 2)
}
