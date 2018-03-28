package filecrypt

import (
	"io"
	"log"
)

// LoggerProxy adds services to the regular logger such as a verbosity flag.
type LoggerProxy struct {
	*log.Logger
	verbose bool
}

// NewLoggerProxy will return a new logger.
func NewLoggerProxy(out io.Writer, prefix string, flag int, verbose bool) *LoggerProxy {
	return &LoggerProxy{log.New(out, prefix, flag), verbose}
}

// Print calls l.Output to print to the logger if verbosity is set.
func (l *LoggerProxy) Print(v ...interface{}) {
	if l.verbose {
		l.Logger.Print(v)
	}
}

// Printf calls l.Output to print to the logger if verbosity is set.
func (l *LoggerProxy) Printf(format string, v ...interface{}) {
	if l.verbose {
		l.Logger.Printf(format, v)
	}
}

// Println calls l.Output to print to the logger if verbosity is set.
func (l *LoggerProxy) Println(msg string) {
	if l.verbose {
		l.Logger.Println(msg)
	}
}
