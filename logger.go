package agent

import (
	"bytes"
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

var dateRegex = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T`)

// globalNetAppender receives matching logger writes if non-nil.
var globalNetAppender *logging.NetAppender

type matcher struct {
	regex   *regexp.Regexp
	channel chan ([]string)
	mask    bool
}

// NewMatchingLogger returns a MatchingLogger.
func NewMatchingLogger(logger logging.Logger, isError, upload bool) *MatchingLogger {
	return &MatchingLogger{logger: logger, defaultError: isError, upload: upload}
}

// MatchingLogger provides a logger that also allows sending regex matched lines to a channel.
type MatchingLogger struct {
	mu           sync.RWMutex
	logger       logging.Logger
	matchers     map[string]matcher
	defaultError bool
	// if upload is true, copy dated lines to globalNetAppender.
	upload bool
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
		return len(p), nil
	}

	// filter out already-timestamped logging from stdout
	if dateRegex.Match(p) {
		if l.upload {
			if parsed := parseLog(p); parsed.valid() && globalNetAppender != nil {
				globalNetAppender.Write(parsed.entry(), nil) //nolint:errcheck,gosec
			}
		}
		n, err := os.Stdout.Write(p)
		if err != nil {
			return n, err
		}
	} else {
		lines := strings.ReplaceAll(strings.TrimSpace(string(p)), "\n", "\n\t")
		if l.defaultError {
			l.logger.Error(fmt.Sprintf("unstructured error output:\n\t%s", lines))
		} else {
			l.logger.Warn(fmt.Sprintf("unstructured output:\n\t%s", lines))
		}
	}

	return len(p), nil
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

func (p parsedLog) valid() bool {
	return len(p.date) > 0 && len(p.level) > 0 && len(p.loggerName) > 0 && len(p.location) > 0 && len(p.tail) > 0
}

var levels = map[string]zapcore.Level{
	"DEBUG":  zapcore.DebugLevel,
	"INFO":   zapcore.InfoLevel,
	"WARN":   zapcore.WarnLevel,
	"ERROR":  zapcore.ErrorLevel,
	"DPANIC": zapcore.DPanicLevel,
	"PANIC":  zapcore.PanicLevel,
	"FATAL":  zapcore.FatalLevel,
}

var colorCodeRegexp = regexp.MustCompile(`\x1b\[\d+m`)

// stripAnsiColorCodes removes color codes from a string so we can use it internally.
func stripAnsiColorCodes(raw []byte) []byte {
	return colorCodeRegexp.ReplaceAll(raw, nil)
}

// entry converts a parsedLog to a zapcore.Entry which can be NetAppender'd.
func (p parsedLog) entry() zapcore.Entry {
	level, ok := levels[string(p.level)]
	if !ok {
		level = zapcore.DebugLevel
	}
	file, rawLine, defined := bytes.Cut(p.location, []byte{':'})
	line, _ := strconv.ParseUint(string(rawLine), 10, 64) //nolint:errcheck
	return zapcore.Entry{
		Level: level,
		// note: time.Now() is basically correct, and simpler than parsing.
		Time:       time.Now().UTC(),
		LoggerName: string(p.loggerName),
		Message:    string(p.tail),
		Caller:     zapcore.EntryCaller{Defined: defined, File: string(file), Line: int(line)},
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
	tokens := bytes.SplitN(line, []byte{'\t'}, 5)
	return &parsedLog{
		date:       getIndexOrNil(tokens, 0),
		level:      stripAnsiColorCodes(getIndexOrNil(tokens, 1)),
		loggerName: getIndexOrNil(tokens, 2),
		location:   getIndexOrNil(tokens, 3),
		tail:       getIndexOrNil(tokens, 4),
	}
}
