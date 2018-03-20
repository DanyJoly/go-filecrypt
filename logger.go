package main

import (
	"io"
	"log"
)

// loggerProxy adds services to the regular logger such as a verbosity flag.
type loggerProxy struct {
	*log.Logger
	verbose bool
}

func newLoggerProxy(out io.Writer, prefix string, flag int, verbose bool) *loggerProxy {
	return &loggerProxy{log.New(out, prefix, flag), verbose}
}

func (l *loggerProxy) Print(v ...interface{}) {
	if l.verbose {
		l.Logger.Print(v)
	}
}

func (l *loggerProxy) Printf(format string, v ...interface{}) {
	if l.verbose {
		l.Logger.Printf(format, v)
	}
}

func (l *loggerProxy) Println(msg string) {
	if l.verbose {
		l.Logger.Println(msg)
	}
}
