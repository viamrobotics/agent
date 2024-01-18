package agent

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type matcher struct {
	regex   *regexp.Regexp
	channel chan ([]string)
	mask    bool
}

// NewMatchingLogger returns a MatchingLogger
func NewMatchingLogger(logger *zap.SugaredLogger, isError bool) *MatchingLogger {
	return &MatchingLogger{logger: logger, defaultError: isError}
}

// MatchingLogger provides a zap logger that also allows sending regex matched lines to a channel.
type MatchingLogger struct {
	mu           sync.RWMutex
	logger       *zap.SugaredLogger
	matchers     map[string]matcher
	defaultError bool
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
	dateRegex := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T`)
	if dateRegex.Match(p) {
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
