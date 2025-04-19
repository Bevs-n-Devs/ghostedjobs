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
	hashEmail, err := db.GetHashEmailFromSessionToken(sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Error getting hash email from session token for create review page: "+err.Error())
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	newSessionToken, newCsrfToken, newExpiryTime, err := db.UpdateProfileSessionTokens(hashEmail)
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

	createViewReviewSessionCookie := middleware.ViewReviewSessionCookie(w, newSessionToken, newExpiryTime)
	if !createViewReviewSessionCookie {
		logs.Logs(logErr, "Error creating view review session cookie")
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}
	createViewReviewCSRFTokenCookie := middleware.ViewReviewCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createViewReviewCSRFTokenCookie {
		logs.Logs(logErr, "Error creating view review CSRF token cookie")
		http.Redirect(w, r, "/#summonYourSpirit?authenticationError=UNAUTHORIZED+401:+Error+authenticating+profile", http.StatusSeeOther)
		return
	}

	createLogoutProfileSessionCookie := middleware.LogoutProfileSessionCookie(w, newSessionToken, newExpiryTime)
	if !createLogoutProfileSessionCookie {
		logs.Logs(logErr, "Error creating logout profile session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createLogoutProfileCSRFTokenCookie := middleware.LogoutProfileCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createLogoutProfileCSRFTokenCookie {
		logs.Logs(logErr, "Error creating logout profile CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
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

	// TODO: replace empty recruiterName & managerName with "Not Provided" in database
	if recruiterName == "" {
		recruiterName = "Not Provided"
	}
	if managerName == "" {
		managerName = "Not Provided"
	}

	// TODO: get hash profile name from database, then encrypt it - this is to enable searching
	hashProfileName, encryptProfileName, err := db.GetUserNameFromHashEmail(hashEmail)
	if err != nil {
		logs.Logs(logErr, "Error getting hash profile name from hash email: "+err.Error())
		http.Error(w, "Error getting hash profile name from hash email: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: hash the company name in order to save - this is to enable searching
	hashCompanyName := utils.HashData(companyName)

	// TODO: encrypt data in order to save
	encryptCompanyName, err := utils.Encrypt([]byte(companyName))
	if err != nil {
		logs.Logs(logErr, "Error encrypting company name: "+err.Error())
		http.Error(w, "Error encrypting company name: "+err.Error(), http.StatusInternalServerError)
		return
	}

	encryptRecruiterName, err := utils.Encrypt([]byte(recruiterName))
	if err != nil {
		logs.Logs(logErr, "Error encrypting recruiter name: "+err.Error())
		http.Error(w, "Error encrypting recruiter name: "+err.Error(), http.StatusInternalServerError)
		return
	}

	encryptManagerName, err := utils.Encrypt([]byte(managerName))
	if err != nil {
		logs.Logs(logErr, "Error encrypting manager name: "+err.Error())
		http.Error(w, "Error encrypting manager name: "+err.Error(), http.StatusInternalServerError)
		return
	}

	encryptReviewContent, err := utils.Encrypt([]byte(reviewContent))
	if err != nil {
		logs.Logs(logErr, "Error encrypting review content: "+err.Error())
		http.Error(w, "Error encrypting review content: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = db.CreateNewReview(hashProfileName, encryptProfileName, hashCompanyName, encryptCompanyName, interactionType, encryptRecruiterName, encryptManagerName, reviewRating, encryptReviewContent)
	if err != nil {
		logs.Logs(logErr, "Error creating new review: "+err.Error())
		http.Error(w, "Error creating new review: "+err.Error(), http.StatusInternalServerError)
		return
	}

	logs.Logs(logInfo, "New review created successfully")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
