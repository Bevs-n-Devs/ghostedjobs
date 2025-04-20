package email

import "os"

const (
	logInfo  = 1
	logWarn  = 2
	logErr   = 3
	smptHost = "smtp.gmail.com"
	smptPort = "587"
)

var (
	smptUser     = os.Getenv("GHOSTEDJOBS_EMAIL") // email address
	smptPassword = os.Getenv("GHOSTEDJOBS_PASSWORD") // email password
	recipient    string // 1st destination email
	ccEmail      = os.Getenv("GHOSTEDJOBS_BACKUP_EMAIL")             // 2nd destination email
)
