package handlers

import (
	"fmt"
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/middleware"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
)

func CreateReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logs.Logs(logErr, fmt.Sprintf("Invalid request method for create review page: %s. Redirecting back to profile login", r.Method))
		http.Redirect(w, r, "/#summonYourSpirit?dRequest=BAD+REQUEST+400:+Invalid+request+method", http.StatusSeeOther)
		return
	}

	err := middleware.AuthenticateProfileRequest(r)
	if err != nil {
		logs.Logs(logErr, "Error authenticating profile for create review page: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	sessionToken, err := utils.CheckSessionToken(r)
	if err != nil {
		logs.Logs(logErr, "Error checking session token for create review page: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	profieEmail, err := db.GetHashEmailFromSessionToken(sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Error getting hash email from session token for create review page: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	newSessionToken, newCsrfToken, newExpiryTime, err := db.UpdateProfileSessionTokens(profieEmail)
	if err != nil {
		logs.Logs(logErr, "Error updating profile session tokens for create review page: "+err.Error())
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

	createNewReviewSessionCookie := middleware.CreateNewReviewSessionCookie(w, newSessionToken, newExpiryTime)
	if !createNewReviewSessionCookie {
		logs.Logs(logErr, "Error creating new review session cookie")
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}
	createNewReviewCSRFTokenCookie := middleware.CreateNewReviewCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createNewReviewCSRFTokenCookie {
		logs.Logs(logErr, "Error creating new review CSRF token cookie")
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	// get form data
	err = r.ParseForm()
	if err != nil {
		logs.Logs(logErr, "Error parsing form data: "+err.Error())
		http.Error(w, "Error parsing form data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// extract data
	companyName := r.FormValue("companyName")
	interactionType := r.FormValue("reviewType")
	recruiterName := r.FormValue("recruiterName")
	managerName := r.FormValue("managerName")
	reviewRating := r.FormValue("reviewRating")
	reviewContent := r.FormValue("reviewContent")

	// save data if no recruiterName AND no managerName is provided
	if recruiterName == "" && managerName == "" {
		err = db.CreateNewReviewWithoutRecruiterAndManager(profieEmail, companyName, interactionType, reviewRating, reviewContent)
		if err != nil {
			logs.Logs(logErr, "Error creating new review without recruiter and manager: "+err.Error())
			http.Error(w, "Error creating new review: "+err.Error(), http.StatusInternalServerError)
			return
		}

		logs.Logs(logInfo, "New review created successfully")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// save data if no recruiterName is provided
	if recruiterName == "" && managerName != "" {
		err = db.CreateNewReviewWithoutRecruiter(profieEmail, companyName, interactionType, reviewRating, reviewContent, managerName)
		if err != nil {
			logs.Logs(logErr, "Error creating new review without recruiter: "+err.Error())
			http.Error(w, "Error creating new review: "+err.Error(), http.StatusInternalServerError)
			return
		}

		logs.Logs(logInfo, "New review created successfully")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// save data if no managerName is provided
	if recruiterName != "" && managerName == "" {
		err = db.CreateNewReviewWithoutManager(profieEmail, companyName, interactionType, reviewRating, reviewContent, recruiterName)
		if err != nil {
			logs.Logs(logErr, "Error creating new review without manager: "+err.Error())
			http.Error(w, "Error creating new review: "+err.Error(), http.StatusInternalServerError)
			return
		}

		logs.Logs(logInfo, "New review created successfully")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// save data if both recruiterName and managerName are provided
	err = db.CreateNewReviewWithRecruiterAndManager(profieEmail, companyName, interactionType, reviewRating, reviewContent, recruiterName, managerName)
	if err != nil {
		logs.Logs(logErr, "Error creating new review with recruiter and manager: "+err.Error())
		http.Error(w, "Error creating new review: "+err.Error(), http.StatusInternalServerError)
		return
	}

	logs.Logs(logInfo, "New review created successfully")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
