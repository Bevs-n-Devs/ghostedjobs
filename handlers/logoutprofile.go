package handlers

import (
	"fmt"
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/middleware"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
)

func LogoutProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		logs.Logs(logErr, "Invalid request method for GHOSTED! search engine: "+r.Method)
		http.Redirect(w, r, fmt.Sprintf("/?badRequest=%s%s", ERROR2, invalidRequestMethod), http.StatusSeeOther)
		return
	}

	sessionToken, err := utils.CheckSessionToken(r)
	if err != nil {
		logs.Logs(logErr, "Session token not found for search engine: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionNotFound), http.StatusSeeOther)
		return
	}
	logs.Logs(logInfo, "Session token: "+sessionToken.Value)

	// validate authorisation request
	err = middleware.AuthenticateProfileRequest(r)
	if err != nil {
		logs.Logs(logErr, "Invalid request method for search engine: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, invalidRequestMethod), http.StatusSeeOther)
		return
	}

	// get hash email from session token
	hashEmail, err := db.GetHashEmailFromSessionToken(sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Session token not found for search engine: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR1, sessionNotFound), http.StatusSeeOther)
		return
	}

	// delete the session token & CSRF token and clear expiry time from database
	err = db.Logout(hashEmail)
	if err != nil {
		logs.Logs(logErr, "failed to logout profile: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, logoutError), http.StatusSeeOther)
	}

	// delete the session token & CSRF token and clear expiry time
	deleteSessionCookie := middleware.DeleteProfileSessionCookie(w)
	if !deleteSessionCookie {
		logs.Logs(logErr, "failed to delete session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, logoutError), http.StatusSeeOther)
		return
	}
	deleteCsrfCookie := middleware.DeleteProfileCSRFCookie(w)
	if !deleteCsrfCookie {
		logs.Logs(logErr, "failed to delete CSRF cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, logoutError), http.StatusSeeOther)
		return
	}

	logs.Logs(logInfo, "profile logged out successfully")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
