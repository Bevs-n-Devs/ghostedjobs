package handlers

import (
	"fmt"
	"net/http"

	"github.com/Bevs-n-Devs/ghostedjobs/db"
	"github.com/Bevs-n-Devs/ghostedjobs/logs"
	"github.com/Bevs-n-Devs/ghostedjobs/middleware"
	"github.com/Bevs-n-Devs/ghostedjobs/tmpl"
	"github.com/Bevs-n-Devs/ghostedjobs/utils"
)

func ProfileReviews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		logs.Logs(logErr, "Invalid request method for GHOSTED! job reviews: "+r.Method)
		http.Redirect(w, r, fmt.Sprintf("/?badRequest=%s%s", ERROR2, invalidRequestMethod), http.StatusSeeOther)
		return
	}

	sessionToken, err := utils.CheckSessionToken(r)
	if err != nil {
		logs.Logs(logErr, "Session token not found for profile dashboard: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionNotFound), http.StatusSeeOther)
		return
	}
	logs.Logs(logInfo, "Session token: "+sessionToken.Value)

	// validate authorisation request
	err = middleware.AuthenticateProfileRequest(r)
	if err != nil {
		logs.Logs(logErr, "Invalid request method for profile dashboard: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, invalidRequestMethod), http.StatusSeeOther)
		return
	}

	// get hash email from session token
	hashEmail, err := db.GetHashEmailFromSessionToken(sessionToken.Value)
	if err != nil {
		logs.Logs(logErr, "Session token not found for profile dashboard: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR1, sessionNotFound), http.StatusSeeOther)
		return
	}

	newSessionToken, newCsrfToken, newExpiryTime, err := db.UpdateProfileSessionTokens(hashEmail)
	if err != nil {
		logs.Logs(logErr, "Error updating session tokens for profile dashboard: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, errorUpdatingSessionTokens), http.StatusSeeOther)
		return
	}

	// TODO! Set cookies for each available page
	createProfileDashboardSessionCookie := middleware.ProfileDashboardSessionCookie(w, newSessionToken, newExpiryTime)
	if !createProfileDashboardSessionCookie {
		logs.Logs(logErr, "Error creating profile dashboard session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createProfileDashboardCSRFTokenCookie := middleware.ProfileDashboardCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createProfileDashboardCSRFTokenCookie {
		logs.Logs(logErr, "Error creating profile dashboard CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}

	createNewReviewSessionCookie := middleware.CreateNewReviewSessionCookie(w, newSessionToken, newExpiryTime)
	if !createNewReviewSessionCookie {
		logs.Logs(logErr, "Error creating new review session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createNewReviewCSRFTokenCookie := middleware.CreateNewReviewCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createNewReviewCSRFTokenCookie {
		logs.Logs(logErr, "Error creating new review CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}

	createViewReviewSessionCookie := middleware.ViewReviewSessionCookie(w, newSessionToken, newExpiryTime)
	if !createViewReviewSessionCookie {
		logs.Logs(logErr, "Error creating view review session cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCookieError), http.StatusSeeOther)
		return
	}
	createViewReviewCSRFTokenCookie := middleware.ViewReviewCSRFTokenCookie(w, newCsrfToken, newExpiryTime)
	if !createViewReviewCSRFTokenCookie {
		logs.Logs(logErr, "Error creating view review CSRF token cookie")
		http.Redirect(w, r, fmt.Sprintf("/?authenticationError=%s%s", ERROR2, sessionCsrfCookieError), http.StatusSeeOther)
		return
	}

	// TODO: get  reviews from database
	getAllReviews, err := db.GetAllGhostedReviews()
	if err != nil {
		logs.Logs(logErr, "Error getting all reviews: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/dashboard?reviewsError=%s%s", ERROR1, reviewsError), http.StatusSeeOther)
		return
	}

	// TODO: decrypt data in order to display
	showAllReviews := []ViewGhostedReviews{}

	logs.Logs(logInfo, "Decrypting Ghosted! reviews data...")
	for index := range getAllReviews {
		var convertedData ViewGhostedReviews

		convertedData.InteractionType = getAllReviews[index].InteractionType
		convertedData.ReviewRating = getAllReviews[index].ReviewRating
		convertedData.CreatedAt = getAllReviews[index].CreatedAt

		// decrypt review data
		companyName, err := utils.Decrypt(getAllReviews[index].CompanyName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting company name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/dashboard?companyNameError=%s%s", ERROR2, decryptCompanyNameError), http.StatusSeeOther)
			return
		}
		convertedData.CompanyName = string(companyName)

		recruiterName, err := utils.Decrypt(getAllReviews[index].RecruiterName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting recruiter name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/dashboard?recruiterNameError=%s%s", ERROR2, decryptRecruiterNameError), http.StatusSeeOther)
			return
		}
		convertedData.RecruiterName = string(recruiterName)

		managerName, err := utils.Decrypt(getAllReviews[index].ManagerName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting manager name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/dashboard?managerNameError=%s%s", ERROR2, decryptManagerNameError), http.StatusSeeOther)
			return
		}
		convertedData.ManagerName = string(managerName)

		reviewContent, err := utils.Decrypt(getAllReviews[index].ReviewContent)
		if err != nil {
			logs.Logs(logErr, "Error decrypting review content: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/dashboard?error=%s%s", ERROR2, decryptReviewContentError), http.StatusSeeOther)
			return
		}
		convertedData.ReviewContent = string(reviewContent)

		profileName, err := utils.Decrypt(getAllReviews[index].ProfileName)
		if err != nil {
			logs.Logs(logErr, "Error decrypting profile name: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/dashboard?error=%s%s", ERROR2, decryptProfileNameError), http.StatusSeeOther)
			return
		}
		convertedData.ProfileName = string(profileName)

		// add data to showAllReviews slice
		showAllReviews = append(showAllReviews, convertedData)
	}

	// create struct in order to pass data to template
	showData := struct {
		Reviews []ViewGhostedReviews
	}{
		Reviews: showAllReviews,
	}

	err = tmpl.Templates.ExecuteTemplate(w, "profiledashboard.html", showData)
	if err != nil {
		logs.Logs(logErr, "Unable to load dashboard page: "+err.Error())
		http.Error(w, "Unable to load dashboard page: "+err.Error(), http.StatusInternalServerError)
	}
}
