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

func TestParseJournalEntry(t *testing.T) {
	logger := logging.NewTestLogger(t)
	matchingLogger := NewMatchingLogger(logger, false, true)

	tests := []struct {
		name   string
		input  []byte
		want   []logging.LogEntry
		wantOk bool
	}{
		{
			name:   "single valid entry",
			input:  []byte(`{"MESSAGE":"test message","PRIORITY":"6","SYSLOG_IDENTIFIER":"test-service","_BOOT_ID":"abc123","__REALTIME_TIMESTAMP":"1234567890000","__MONOTONIC_TIMESTAMP":"1000000"}`),
			wantOk: true,
			want: []logging.LogEntry{
				{
					Entry: zapcore.Entry{
						Level:      zapcore.InfoLevel,
						LoggerName: logger.Desugar().Name(),
						Message:    "[syslog_id=test-service boot_id=abc123 realtime=1970-01-15T06:56:07.89Z monotonic=1ms since boot] test message",
						Caller:     zapcore.EntryCaller{Defined: false},
					},
				},
			},
		},
		{
			name: "multiple entries",
			input: []byte(`{"MESSAGE":"error message","PRIORITY":"3","SYSLOG_IDENTIFIER":"error-service","_BOOT_ID":"abc123","__REALTIME_TIMESTAMP":"1234567890000","__MONOTONIC_TIMESTAMP":"1000000"}
{"MESSAGE":"warning message","PRIORITY":"4","SYSLOG_IDENTIFIER":"warn-service","_BOOT_ID":"abc123","__REALTIME_TIMESTAMP":"1234567890000","__MONOTONIC_TIMESTAMP":"1000000"}`),
			wantOk: true,
			want: []logging.LogEntry{
				{
					Entry: zapcore.Entry{
						Level:      zapcore.ErrorLevel,
						LoggerName: logger.Desugar().Name(),
						Message:    "[syslog_id=error-service boot_id=abc123 realtime=1970-01-15T06:56:07.89Z monotonic=1ms since boot] error message",
						Caller:     zapcore.EntryCaller{Defined: false},
					},
				},
				{
					Entry: zapcore.Entry{
						Level:      zapcore.WarnLevel,
						LoggerName: logger.Desugar().Name(),
						Message:    "[syslog_id=warn-service boot_id=abc123 realtime=1970-01-15T06:56:07.89Z monotonic=1ms since boot] warning message",
						Caller:     zapcore.EntryCaller{Defined: false},
					},
				},
			},
		},
		{
			name:   "invalid JSON",
			input:  []byte(`invalid json`),
			wantOk: false,
			want:   nil,
		},
		{
			name:   "missing required fields",
			input:  []byte(`{"PRIORITY":"6","SYSLOG_IDENTIFIER":"test-service"}`),
			wantOk: false,
			want:   nil,
		},
		{
			name:   "empty input",
			input:  []byte{},
			wantOk: false,
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := matchingLogger.parseJournalEntry(tt.input)
			test.That(t, ok, test.ShouldEqual, tt.wantOk)
			if tt.wantOk {
				test.That(t, len(got), test.ShouldEqual, len(tt.want))
				for i, entry := range got {
					test.That(t, entry.Entry.Level, test.ShouldEqual, tt.want[i].Entry.Level)
					test.That(t, entry.Entry.Message, test.ShouldEqual, tt.want[i].Entry.Message)
					test.That(t, entry.Entry.LoggerName, test.ShouldEqual, tt.want[i].Entry.LoggerName)
					test.That(t, entry.Entry.Caller, test.ShouldResemble, tt.want[i].Entry.Caller)
				}
			}
		})
	}
}
