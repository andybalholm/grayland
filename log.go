package main

import (
	"bytes"
	"fmt"
	"log"
	"log/syslog"
	"os"
)

var logWriter *syslog.Writer

func init() {
	var err error
	logWriter, err = syslog.New(syslog.LOG_INFO|syslog.LOG_MAIL, "grayland")
	if err != nil {
		log.Fatal("Error connecting to syslog: ", err)
	}
	log.SetOutput(logWriter)
	log.SetFlags(0)
}

func formatLog(s ...interface{}) string {
	buf := new(bytes.Buffer)

	if len(s)%2 == 1 {
		msg := s[0]
		s = s[1:]
		fmt.Fprint(buf, msg)
		if len(s) > 0 {
			buf.WriteString(": ")
		}
	}

	for i := 0; i < len(s)-1; i += 2 {
		if i > 0 {
			buf.WriteString(", ")
		}
		fmt.Fprint(buf, s[i], "=", s[i+1])
	}

	return string(buf.Bytes())
}

// Log writes a message to the system log. The parameters are an optional
// initial message, and any number of key/value pairs giving additional
// information.
func Log(s ...interface{}) {
	logWriter.Info(formatLog(s...))
}

// Fatal is like Log, but it terminates the program.
func Fatal(s ...interface{}) {
	logWriter.Crit(formatLog(s...))
	os.Exit(1)
}
