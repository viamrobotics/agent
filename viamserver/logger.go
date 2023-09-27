package viamserver

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
}

// MatchingLogger provides a zap logger that also allows sending regex matched lines to a channel.
type MatchingLogger struct {
	mu       sync.RWMutex
	logger   *zap.SugaredLogger
	matchers map[string]matcher
	defaultError bool
}

func (l *MatchingLogger) AddMatcher(name string, regex *regexp.Regexp) (<-chan []string, error) {
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
	l.matchers[name] = matcher{regex: regex, channel: c}
	return c, nil
}

func (l *MatchingLogger) DeleteMatcher(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.matchers[name]
	if ok {
		close(m.channel)
		delete(l.matchers, name)
	}
}

func (l *MatchingLogger) Write(p []byte) (int, error) {
	// filter out already-timestamped logging from stdout
	dateRegex := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T`)
	if dateRegex.Match(p) {
		os.Stdout.Write(p)
	} else {
		lines := strings.Replace(strings.TrimSpace(string(p)), "\n", "\n\t", -1)
		if l.defaultError {
			l.logger.Error(fmt.Sprintf("unstructured error output:\n\t%s", lines))
		}else{
			l.logger.Warn(fmt.Sprintf("unstructured output:\n\t%s", lines))
		}
	}

	// send matches to channel(s)
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, m := range l.matchers {
		matches := m.regex.FindStringSubmatch(string(p))
		if matches != nil {
			m.channel <- matches
		}
	}
	return len(p), nil
}
