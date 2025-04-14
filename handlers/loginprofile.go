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
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// TODO: get data from form to login
	err := r.ParseForm()
	if err != nil {
		logs.Logs(logErr, "Error parsing form data: "+err.Error())
		http.Error(w, "Error parsing form data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// extract form data
	profileName := r.FormValue("profileName")
	profileEmail := r.FormValue("profileEmail")
	profilePassword := r.FormValue("profilePassword")

	logs.Logs(logInfo, "Login attempt for profile: "+profileName+" with email: "+profileEmail)

	// TODO: hash profile name, email and password
	hashedProfileName := utils.HashData(profileName)
	hashedProfileEmail := utils.HashData(profileEmail)
	hashedProfilePassword := utils.HashData(profilePassword)

	// TODO: validate user via AuthenticateProfile function (in db package)
	authenticateProfile, err := db.AuthenticateProfile(hashedProfileName, hashedProfileEmail, hashedProfilePassword)
	if err != nil {
		logs.Logs(logErr, "Error authenticating profile: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?error=Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	if !authenticateProfile {
		logs.Logs(logErr, "Profile does not exists: "+profileName)
		http.Redirect(w, r, "/#summonYourSpirit?error=Profile+does+not+exist", http.StatusSeeOther)
		return
	}

	// TODO: update the profile session tokens in the database
	newSessionToken, newCsrfToken, newExpiryTime, err := db.UpdateProfileSessionTokens(hashedProfileEmail)
	if err != nil {
		logs.Logs(logErr, "Error updating profile session tokens: "+err.Error())
		http.Error(w, "Error updating profile session tokens: "+err.Error(), http.StatusInternalServerError)
		return
	}

	logs.Logs(logInfo, "Generated new session token: "+newSessionToken)

	// TODO: create session tokens for login page
	createProfileDashboardSessionCookie := middleware.ProfileDashboardSessionCookie(w, newSessionToken, newExpiryTime)
	if !createProfileDashboardSessionCookie {
		logs.Logs(logErr, "Error creating profile dashboard session cookie")
		http.Error(w, "Error creating profile dashboard session cookie", http.StatusInternalServerError)
		return
	}

	// Verify the cookie was set correctly
	cookies := w.Header()["Set-Cookie"]
	logs.Logs(logInfo, "Set cookies: "+strings.Join(cookies, ", "))

	createProfileDashboardCSRFTokenCookie := middleware.ProfileDashboardCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createProfileDashboardCSRFTokenCookie {
		logs.Logs(logErr, "Error creating profile dashboard CSRF token cookie")
		http.Error(w, "Error creating profile dashboard CSRF token cookie", http.StatusInternalServerError)
		return
	}
	logs.Logs(logInfo, "Profile session and CSRF token cookies created successfully")

	// TODO: redirect to dashboard page if successful
	logs.Logs(logInfo, "Redirecting user to profile dashboard page")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
