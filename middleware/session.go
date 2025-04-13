package middleware

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
)

const (
	logInfo = 1
	logErr  = 3
)

var errAuth = errors.New("user not authenticated")

func AuthenticateProfileRequest(r *http.Request) error {
	sessionToken, err := utils.CheckSessionToken(r)
	if err != nil {
		logs.Logs(logErr, "Session token not found: "+err.Error())
		return fmt.Errorf("session token not found: %s", err.Error())
	}
	logs.Logs(logInfo, "Session token: "+sessionToken.Value)

	hashEmail, err := db.GetHashEmailFromSessionToken(sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Failed to get the hash email from session token: "+err.Error())
		return fmt.Errorf("failed to get the hash email from session token: %s", errAuth)
	}

	// check if the hash email and session token exists in the database
	exists, err := db.ValidateProfileSessionTokenFromHashEmail(hashEmail, sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Failed to validate profile session token from hash email: "+err.Error())
		return fmt.Errorf("failed to validate profile session token from hash email: %s", errAuth)
	}
	if !exists {
		logs.Logs(logErr, "Invalid profile session token")
		return fmt.Errorf("invalid profile session token: %s", errAuth)
	}
	logs.Logs(logInfo, "Profile session validation result: "+fmt.Sprintf("%t", exists))

	csrfToken, err := utils.CheckCSRFToken(r)
	if err != nil {
		logs.Logs(logErr, "CSRF token not found: "+err.Error())
		return fmt.Errorf("CSRF token not found: %s", errAuth)
	}

	// check if the csrf token and session token exists in the database
	exists, err = db.ValidateProfileCSRFTokenFromHashEmail(hashEmail, csrfToken.Value)
	if err != nil {
		logs.Logs(logErr, "Failed to validate profile csrf token from hash email: "+err.Error())
		return fmt.Errorf("failed to validate profile csrf token from hash email: %s", errAuth)
	}
	if !exists {
		logs.Logs(logErr, "Invalid profile csrf token")
		return fmt.Errorf("invalid profile csrf token: %s", errAuth)
	}
	logs.Logs(logInfo, "Profile CSRF validation result: "+fmt.Sprintf("%t", exists))

	return nil
}
