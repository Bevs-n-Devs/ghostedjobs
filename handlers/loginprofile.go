package handlers

import (
	"fmt"
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/middleware"
)

func LoginProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logs.Logs(logErr, fmt.Sprintf("Invalid request method: %s. Redirecting back to home page", r.Method))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

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

	// Validate the profile name, email and password
	profileNameExists := db.CheckProfileName(profileName)
	if !profileNameExists {
		logs.Logs(logErr, "Profile name does not exist: "+profileName)
		http.Redirect(w, r, "/#summonYourSpirit?error=invalid_credentials", http.StatusSeeOther)
		return
	}
	profileEmailExists := db.CheckProfileEmail(profileEmail)
	if !profileEmailExists {
		logs.Logs(logErr, "Profile email does not exist: "+profileEmail)
		http.Redirect(w, r, "/#summonYourSpirit?error=invalid_credentials", http.StatusSeeOther)
		return
	}
	profilePasswordExists := db.ValidateProfilePassword(profilePassword)
	if !profilePasswordExists {
		logs.Logs(logErr, "Profile password does not exist: "+profilePassword)
		http.Redirect(w, r, "/#summonYourSpirit?error=invalid_credentials", http.StatusSeeOther)
		return
	}

	// Create cookies to send to user dashboard page
	sessionToken, csrfToken, expiryTime, err := db.UpdateProfileSessionTokens(profileEmail)
	if err != nil {
		logs.Logs(logErr, "Error updating profile session tokens: "+err.Error())
		http.Error(w, "Error updating profile session tokens: "+err.Error(), http.StatusInternalServerError)
		return
	}

	createProfileDashboardSessionCookie := middleware.ProfileDashboardSessionCookie(w, sessionToken, expiryTime)
	if !createProfileDashboardSessionCookie {
		logs.Logs(logErr, "Error creating profile dashboard session cookie")
		http.Error(w, "Error creating profile dashboard session cookie", http.StatusInternalServerError)
		return
	}

	createProfileDashboardCSRFTokenCookie := middleware.ProfileDashboardCSRFTokenCookie(w, csrfToken, expiryTime)
	if !createProfileDashboardCSRFTokenCookie {
		logs.Logs(logErr, "Error creating profile dashboard CSRF token cookie")
		http.Error(w, "Error creating profile dashboard CSRF token cookie", http.StatusInternalServerError)
		return
	}
	logs.Logs(logInfo, "Profile session and CSRF token cookies created successfully")

	// Redirect user to dashboard page
	logs.Logs(logInfo, "Redirecting user to profile dashboard page")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
