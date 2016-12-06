package logutil

import (
	log "github.com/Sirupsen/logrus"
	"github.com/hashicorp/errwrap"
)

// Entry wraps the normal log entry type to add support for custom With
// functions
type Entry struct {
	*log.Entry
}

// NewEntry wraps a *logrus.Entry in the custom Entry type.
func NewEntry(entry *log.Entry) *Entry {
	return &Entry{
		entry,
	}
}

// WithErrors unwraps and expands an errwrap error to show nested errors
func (entry *Entry) WithErrors(err error) *Entry {
	flattenedErrors := []string{}
	errwrap.Walk(err, func(wrappedErr error) {
		// TODO(wrouesnel): this is the wrong way to do this, but it works for now.
		flattenedErrors = append(flattenedErrors, wrappedErr.Error())
	})
	return NewEntry(entry.Entry.WithField("errors", flattenedErrors))
}

// WithError adds an error as single field (using the key defined in ErrorKey) to the Entry.
func (entry *Entry) WithError(err error) *Entry {
	return NewEntry(entry.Entry.WithError(err))
}

// WithField adds a single field to the Entry.
func (entry *Entry) WithField(key string, value interface{}) *Entry {
	return NewEntry(entry.Entry.WithField(key, value))
}

// WithFields adds a map of fields to the Entry.
func (entry *Entry) WithFields(fields log.Fields) *Entry {
	return NewEntry(entry.Entry.WithFields(fields))
}
