package main

import (
	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/handlers"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
)

const (
	logInfo  = 1
	logDbErr = 5
)

func main() {
	go logs.LogProcessor()
	logs.Logs(logInfo, "Welcome to GHOSTED! A we app that allows users to report bad hiring practices.")

	err := db.ConnectDB()
	if err != nil {
		logs.Logs(logDbErr, "Error connecting to database: "+err.Error())
		return
	}

	go handlers.StartHTTPServer()

	select {} // keets the program running
}
