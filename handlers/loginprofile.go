package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/middleware"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
)

func LoginProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logs.Logs(logErr, fmt.Sprintf("Invalid request method: %s. Redirecting back to home page", r.Method))
		http.Redirect(w, r, fmt.Sprintf("/?badRequest=%s%s", ERROR2, invalidRequestMethod), http.StatusSeeOther)
		return
	}

	// TODO: get data from form to login
	err := r.ParseForm()
	if err != nil {
		logs.Logs(logErr, "Error parsing form data: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?internalServerError=%s%s", ERROR2, errorParsingData), http.StatusSeeOther)
		return
	}

	// extract form data
	profileName := r.FormValue("profileName")
	profileEmail := r.FormValue("profileEmail")
	profilePassword := r.FormValue("profilePassword")

	// TODO: hash profile name, email and password
	hashedProfileName := utils.HashData(profileName)
	hashedProfileEmail := utils.HashData(profileEmail)
	hashedProfilePassword := utils.HashData(profilePassword)

	// TODO: validate user via AuthenticateProfile function (in db package)
	authenticateProfile, err := db.AuthenticateProfile(hashedProfileName, hashedProfileEmail, hashedProfilePassword)
	if err != nil {
		logs.Logs(logErr, "Error authenticating profile: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR1, profileAuthenticationError), http.StatusSeeOther)
		return
	}

	if !authenticateProfile {
		logs.Logs(logErr, "Profile does not exists: "+profileName)
		http.Redirect(w, r, fmt.Sprintf("/?notFoundError=%s%s", ERROR1, profileNotFound), http.StatusSeeOther)
		return
	}

	// TODO: update the profile session tokens in the database
	newSessionToken, newCsrfToken, newExpiryTime, err := db.UpdateProfileSessionTokens(hashedProfileEmail)
	if err != nil {
		logs.Logs(logErr, "Error updating profile session tokens: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?inernalServerError=%s%s", ERROR2, errorUpdatingSessionTokens), http.StatusSeeOther)
		return
	}

	logs.Logs(logInfo, "Generated new session token: "+newSessionToken)

	// TODO: create session tokens for login page
	createProfileDashboardSessionCookie := middleware.ProfileDashboardSessionCookie(w, newSessionToken, newExpiryTime)
	if !createProfileDashboardSessionCookie {
		logs.Logs(logErr, "Error creating profile dashboard session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?inernalServerError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}

	// Verify the cookie was set correctly
	cookies := w.Header()["Set-Cookie"]
	logs.Logs(logInfo, "Set cookies: "+strings.Join(cookies, ", "))

	createProfileDashboardCSRFTokenCookie := middleware.ProfileDashboardCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createProfileDashboardCSRFTokenCookie {
		logs.Logs(logErr, "Error creating profile dashboard CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?inernalServerError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}
	logs.Logs(logInfo, "Profile session and CSRF token cookies created successfully")

	// TODO: redirect to dashboard page if successful
	logs.Logs(logInfo, "Redirecting user to profile dashboard page")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
