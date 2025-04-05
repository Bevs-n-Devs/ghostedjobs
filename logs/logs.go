package logs

import "log"

var logChannel = make(chan string) // channel to send logs to

const (
	info   = "INFO: "
	warn   = "WARNING! "
	logErr = "ERROR! "
	db     = "DATABASE: "
	dbErr  = "DATABASE ERROR: "
)

func LogProcessor() {
	for logMessage := range logChannel {
		log.Println(logMessage)
	}
}

/*
Logs writes a log message to the log channel, prefixed with one of the log levels defined as constants above.
The log levels are:

1: INFO

2: WARNING

3: ERROR

4: DATABASE

5: DATABASE ERROR
*/
func Logs(logType int, logMessage string) {
	var loggedMessage string
	switch logType {
	case 1:
		loggedMessage = info + logMessage
	case 2:
		loggedMessage = warn + logMessage
	case 3:
		loggedMessage = logErr + logMessage
	case 4:
		loggedMessage = db + logMessage
	case 5:
		loggedMessage = dbErr + logMessage
	}
	logChannel <- loggedMessage
}
