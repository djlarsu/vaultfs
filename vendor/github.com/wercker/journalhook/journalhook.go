package journalhook

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/coreos/go-systemd/journal"
	logrus "github.com/wrouesnel/go.log"
)

type JournalHook struct{}

var (
	severityMap = map[log.Level]journal.Priority{
		log.DebugLevel: journal.PriDebug,
		log.InfoLevel:  journal.PriInfo,
		log.WarnLevel:  journal.PriWarning,
		log.ErrorLevel: journal.PriErr,
		log.FatalLevel: journal.PriCrit,
		log.PanicLevel: journal.PriEmerg,
	}
)

func stringifyOp(r rune) rune {
	// Journal wants uppercase strings. See `validVarName`
	// https://github.com/coreos/go-systemd/blob/ff118ad0f8d9cf99903d3391ca3a295671022cee/journal/journal.go#L137-L147
	switch {
	case r >= 'A' && r <= 'Z':
		return r
	case r >= '0' && r <= '9':
		return r
	case r == '_':
		return r
	case r >= 'a' && r <= 'z':
		return r - 32
	default:
		return rune('_')
	}
}

func stringifyKey(key string) string {
	key = strings.Map(stringifyOp, key)
	if strings.HasPrefix(key, "_") {
		key = strings.TrimPrefix(key, "_")
	}
	return key
}

// Journal wants strings but logrus takes anything.
func stringifyEntries(data map[string]interface{}) map[string]string {
	entries := make(map[string]string)
	for k, v := range data {

		key := stringifyKey(k)
		entries[key] = fmt.Sprint(v)
	}
	return entries
}

func (hook *JournalHook) Fire(entry *log.Entry) error {
	return journal.Send(entry.Message, severityMap[entry.Level], stringifyEntries(entry.Data))
}

// `Levels()` returns a slice of `Levels` the hook is fired for.
func (hook *JournalHook) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
	}
}

// Adds the Journal hook if journal is enabled
// Sets log output to ioutil.Discard so stdout isn't captured.
func Enable() {
	if !journal.Enabled() {
		log.Warning("Journal not available but user requests we log to it. Ignoring")
	} else {
		log.AddHook(&JournalHook{})
		log.SetOutput(ioutil.Discard)
	}
}
