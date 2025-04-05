package utils

import (
	"fmt"
	"os"

	"github.com/Bevs-n-Devs/ghostedjobs/env"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
)

const (
	logInfo = 1
	logWarn = 2
	logErr  = 3
)

var (
	masterKeyStr string // get the MASTER_KEY string from envrionment variable
	masterKey    []byte // convert the MASTER_KEY into 32 bytes for encrytion & decryption process
)

func getMasterKeyStr() error {
	if os.Getenv("MASTER_KEY") == "" {
		logs.Logs(logWarn, "Could not get MASTER_KEY from hosting platform. Loading from .env file...")
		err := env.LoadEnv("env/.env")
		if err != nil {
			logs.Logs(logErr, fmt.Sprintf("Unable to load environment variables: %s", err.Error()))
			return err
		}
	}

	masterKeyStr = os.Getenv("MASTER_KEY")
	if masterKeyStr == "" {
		logs.Logs(logErr, "MASTER_KEY is empty!")
		return fmt.Errorf("MASTER_KEY is empty")
	}

	masterKey = []byte(masterKeyStr)[:32]
	return nil
}

func InitEncryption() error {
	logs.Logs(logInfo, "Initializing encryption functions...")
	err := getMasterKeyStr()
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error getting master key: %s", err.Error()))
		return err
	}
	logs.Logs(logInfo, "Encryption functions successfully initialized.")
	return nil
}
