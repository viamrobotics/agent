package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
	"go.viam.com/rdk/logging"
)

var (
	dateRegex       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T`)
	colorCodeRegexp = regexp.MustCompile(`\x1b\[\d+m`)
)

var levels = map[string]zapcore.Level{
	"DEBUG":  zapcore.DebugLevel,
	"INFO":   zapcore.InfoLevel,
	"WARN":   zapcore.WarnLevel,
	"ERROR":  zapcore.ErrorLevel,
	"DPANIC": zapcore.DPanicLevel,
	"PANIC":  zapcore.PanicLevel,
	"FATAL":  zapcore.FatalLevel,
}

type matcher struct {
	regex   *regexp.Regexp
	channel chan ([]string)
	mask    bool
}

// NewMatchingLogger returns a MatchingLogger.
func NewMatchingLogger(logger logging.Logger, isError, uploadAll bool) *MatchingLogger {
	return &MatchingLogger{logger: logger, defaultError: isError, uploadAll: uploadAll}
}

// MatchingLogger provides a logger that also allows sending regex matched lines to a channel.
type MatchingLogger struct {
	mu           sync.RWMutex
	logger       logging.Logger
	matchers     map[string]matcher
	defaultError bool
	// if uploadAll is false, only send unstructured log lines to the logger, and just print structured ones.
	uploadAll bool
}

// AddMatcher adds a named regex to filter from results and return to a channel, optionally masking it from normal logging.
func (l *MatchingLogger) AddMatcher(name string, regex *regexp.Regexp, mask bool) (<-chan []string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.matchers == nil {
		l.matchers = make(map[string]matcher)
	}
	_, ok := l.matchers[name]
	if ok {
		return nil, errors.Errorf("matcher already exists: %s", name)
	}
	c := make(chan []string, 32)
	l.matchers[name] = matcher{regex: regex, channel: c, mask: mask}
	return c, nil
}

// DeleteMatcher removes a previously added matcher.
func (l *MatchingLogger) DeleteMatcher(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.matchers[name]
	if ok {
		close(m.channel)
		delete(l.matchers, name)
	}
}

// Write takes input and filters it against each defined matcher, before logging it.
func (l *MatchingLogger) Write(p []byte) (int, error) {
	var mask bool

	// send matches to channel(s)
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, m := range l.matchers {
		matches := m.regex.FindStringSubmatch(string(p))
		if matches != nil {
			m.channel <- matches
			if m.mask {
				mask = true
			}
		}
	}

	if mask {
		// If the capture line matches any matcher and m.mask=true,
		// don't republish it below.
		return len(p), nil
	}

	// Try to parse journalctl JSON log entries first.
	if bytes.Contains(p, []byte(`"MESSAGE"`)) && bytes.Contains(p, []byte(`"PRIORITY"`)) && bytes.Contains(p, []byte(`"SYSLOG_IDENTIFIER"`)) {
		if entries, ok := l.parseJournalEntry(p); ok {
			for _, entry := range entries {
				l.logger.Write(&entry)
			}
			return len(p), nil
		}
	}

	// TODO(RSDK-7895): the lines from subprocess stdout are sometimes multi-line.
	dateMatched := dateRegex.Match(p)
	if !dateMatched { //nolint:gocritic
		// this case is the 'unstructured error' case; we were unable to parse a date.
		lines := strings.ReplaceAll(strings.TrimSpace(string(p)), "\n", "\n\t")
		entry := logging.LogEntry{Entry: zapcore.Entry{
			Level:      zapcore.Level(logging.WARN),
			Time:       time.Now().UTC(),
			LoggerName: l.logger.Desugar().Name(),
			Message:    fmt.Sprintf("unstructured output:\n\t%s", lines),
			Caller:     zapcore.EntryCaller{Defined: false},
		}}
		if l.defaultError {
			entry.Level = zapcore.Level(logging.ERROR)
		}
		l.logger.Write(&entry)
	} else if l.uploadAll {
		// in this case, date matching succeeded and we think this is a parseable log message.
		// we check uploadAll because some subprocesses have their own netlogger which will
		// upload structured logs. (But won't upload unmatched logs).
		entry := parseLog(p).entry()
		l.logger.Write(&logging.LogEntry{Entry: entry})
	} else {
		// this case is already-structured logging from non-uploadAll; we print it but don't upload it.
		return os.Stdout.Write(p)
	}
	// note: this return isn't quite right; we don't know how many bytes we wrote, it can be greater
	// than len(p) in some cases, and we don't know if the write succeeded (to stderr or network).
	// Basically we are telling the caller not to retry part of the line.
	return len(p), nil
}

// parseJournalEntry attempts to parse journalctl JSON log entries.
// Returns a slice of LogEntry and true if successful, or nil and false if not.
func (l *MatchingLogger) parseJournalEntry(p []byte) ([]logging.LogEntry, bool) {
	// Split the input into lines to handle multiple JSON entries
	lines := bytes.Split(p, []byte("\n"))
	var entries []logging.LogEntry
	var parseErrors []string

	for i, line := range lines {
		if len(line) == 0 {
			continue
		}

		// Clean up the line - remove any leading/trailing whitespace and ensure it starts with {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("{")) {
			// Try to find the first { and start from there
			if idx := bytes.Index(line, []byte("{")); idx != -1 {
				line = line[idx:]
			} else {
				parseErrors = append(parseErrors, fmt.Sprintf("line %d: no JSON object found", i))
				continue
			}
		}

		var journalEntry struct {
			Message          string `json:"MESSAGE"`
			Priority         string `json:"PRIORITY"`
			SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
			BootID           string `json:"_BOOT_ID"`
			RealtimeTS       string `json:"__REALTIME_TIMESTAMP"`
			MonotonicTS      string `json:"__MONOTONIC_TIMESTAMP"`
		}
		if err := json.Unmarshal(line, &journalEntry); err != nil || journalEntry.Message == "" {
			// Log the error but continue processing other lines
			parseErrors = append(parseErrors, fmt.Sprintf("line %d: %v", i, err))
			continue
		}

		level := zapcore.InfoLevel
		// Priority levels from systemd journal (https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html#PRIORITY=)
		switch journalEntry.Priority {
		case "0", "1", "2", "3": // emerg, alert, crit, err
			level = levels["ERROR"]
		case "4": // warning
			level = levels["WARN"]
		case "5": // notice
			level = levels["INFO"]
		case "6": // info
			level = levels["INFO"]
		case "7": // debug
			level = levels["DEBUG"]
		}

		// Convert timestamps to readable format
		realtime := "unknown"
		if ts, err := strconv.ParseInt(journalEntry.RealtimeTS, 10, 64); err == nil {
			realtime = time.Unix(0, ts*1000).UTC().Format(time.RFC3339Nano)
		}

		// __MONOTONIC_TIMESTAMP is in microseconds since boot
		// See: https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html#__MONOTONIC_TIMESTAMP=
		monotonic := "unknown"
		if ts, err := strconv.ParseInt(journalEntry.MonotonicTS, 10, 64); err == nil {
			monotonic = fmt.Sprintf("%s since boot", time.Duration(ts).String())
		}

		// Format message with additional context
		message := journalEntry.Message
		context := []string{}

		context = append(context, fmt.Sprintf("syslog_id=%s", journalEntry.SyslogIdentifier))
		context = append(context, fmt.Sprintf("boot_id=%s", journalEntry.BootID))
		context = append(context, fmt.Sprintf("realtime=%s", realtime))
		context = append(context, fmt.Sprintf("monotonic=%s", monotonic))
		message = fmt.Sprintf("[%s] %s", strings.Join(context, " "), message)

		entries = append(entries, logging.LogEntry{Entry: zapcore.Entry{
			Level:      level,
			Time:       time.Now().UTC(),
			LoggerName: l.logger.Desugar().Name(),
			Message:    message,
			Caller:     zapcore.EntryCaller{Defined: false},
		}})
	}

	if len(entries) == 0 {
		return nil, false
	}

	return entries, true
}

// parsedLog is a lightweight log structure we parse from subsystem logs.
// Another approach for capturing logs from subsystems is to pass around
// LogEntry or opentelemetry structs.
type parsedLog struct {
	date       []byte
	level      []byte
	loggerName []byte
	location   []byte
	tail       []byte
}

// this returns false if any of the fields is empty.
func (p parsedLog) valid() bool {
	return len(p.date) > 0 && len(p.level) > 0 && len(p.loggerName) > 0 && len(p.location) > 0 && len(p.tail) > 0
}

// stripAnsiColorCodes removes color codes from a string so we can use it internally.
func stripAnsiColorCodes(raw []byte) []byte {
	return colorCodeRegexp.ReplaceAll(raw, nil)
}

// entry converts a parsedLog to a zapcore.Entry which can be NetAppender'd.
func (p parsedLog) entry() zapcore.Entry {
	level, ok := levels[string(p.level)]
	if !ok {
		level = zapcore.WarnLevel
	}
	file, rawLine, defined := bytes.Cut(p.location, []byte{':'})
	line, _ := strconv.Atoi(string(rawLine)) //nolint:errcheck
	return zapcore.Entry{
		Level: level,
		// note: time.Now() is basically correct, and simpler than parsing.
		Time:       time.Now().UTC(),
		LoggerName: string(p.loggerName),
		Message:    string(p.tail),
		Caller:     zapcore.EntryCaller{Defined: defined, File: string(file), Line: line},
	}
}

// getIndexOrNil returns the element at `index` of `arr`, or nil if out of range.
func getIndexOrNil[T any](arr [][]T, index int) []T {
	if index < len(arr) {
		return arr[index]
	}
	return nil
}

func parseLog(line []byte) *parsedLog {
	line = bytes.TrimRight(line, "\r\n")
	tokens := bytes.SplitN(line, []byte{'\t'}, 5)
	parsed := &parsedLog{
		date:       getIndexOrNil(tokens, 0),
		level:      stripAnsiColorCodes(getIndexOrNil(tokens, 1)),
		loggerName: getIndexOrNil(tokens, 2),
		location:   getIndexOrNil(tokens, 3),
		tail:       getIndexOrNil(tokens, 4),
	}
	if !parsed.valid() {
		// in the invalid parse case, we produce a fallback message with the entire line.
		parsed = &parsedLog{
			date:       []byte{' '},
			level:      []byte("WARN"),
			loggerName: []byte("viam-agent.logparse-fail"),
			location:   []byte{' '},
			tail:       line,
		}
	}
	return parsed
}
