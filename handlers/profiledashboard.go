package handlers

import (
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/middleware"
	"github.com/Bevs-n-Devs/ghostedjobs/tmpl"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
)

func ProfileDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		logs.Logs(logErr, "Invalid request method: "+r.Method)
		http.Redirect(w, r, "/#summonYourSpirit?dRequest=BAD+REQUEST+400:+Invalid+request+method", http.StatusSeeOther)
	}

	// validate authorisation request
	err := middleware.AuthenticateProfileRequest(r)
	if err != nil {
		logs.Logs(logErr, "Invalid request method: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	sessionToken, err := utils.CheckSessionToken(r)
	if err != nil {
		logs.Logs(logErr, "Session token not found: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	// get hash email from session token
	hashEmail, err := db.GetHashEmailFromSessionToken(sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Session token not found: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	newSessionToken, newCsrfToken, newExpiryTime, err := db.UpdateProfileSessionTokens(hashEmail)
	if err != nil {
		logs.Logs(logErr, "Error updating session tokens: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	// TODO! Set cookies for each available page
	createProfileDashboardSessionCookie := middleware.ProfileDashboardSessionCookie(w, newSessionToken, newExpiryTime)
	if !createProfileDashboardSessionCookie {
		logs.Logs(logErr, "Error creating profile dashboard session cookie")
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}
	createProfileDashboardCSRFTokenCookie := middleware.ProfileDashboardCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createProfileDashboardCSRFTokenCookie {
		logs.Logs(logErr, "Error creating profile dashboard CSRF token cookie")
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	err = tmpl.Templates.ExecuteTemplate(w, "profiledashboard.html", nil)
	if err != nil {
		logs.Logs(logErr, "Unable to load dashboard page: "+err.Error())
		http.Error(w, "Unable to load dashboard page: "+err.Error(), http.StatusInternalServerError)
	}
}
